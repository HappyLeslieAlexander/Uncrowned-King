//! End-to-end tests for the opt-in transport masking layer (TLS/TCP carrier).
//!
//! Covers the Phase 1a acceptance criteria from
//! `docs/transport-masking-plan.md`:
//!
//! - a full masked flow (prelude → masked TLS → challenge auth → TCP relay),
//! - silent rejection of blind garbage probes (zero response bytes),
//! - replay rejection of a duplicated prelude,
//! - fail-closed behavior on client/server masking mismatches in both
//!   directions,
//! - Prometheus exposition of the masking counters.

use std::{
    error::Error,
    fs, io, process,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use bytes::BytesMut;
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_rustls::TlsConnector;
use uk_client::{
    config::{ClientConfig, ClientMaskingConfig},
    connect_authenticated_carrier,
};
use uk_mask::{ClientPrelude, MaskKeys, MaskedStream, NONCE_LEN, PRELUDE_LEN, PreludePolicy};
use uk_proto::{
    Frame, FrameLimits, FrameType, TCP_OPEN_FLAGS_NONE, Target, TcpOpen, read_frame, write_frame,
};

fn target_from_socket_addr(target_addr: std::net::SocketAddr) -> Target {
    match target_addr {
        std::net::SocketAddr::V4(addr) => Target::Ipv4(*addr.ip(), addr.port()),
        std::net::SocketAddr::V6(addr) => Target::Ipv6(*addr.ip(), addr.port()),
    }
}
use uk_server::config::{CredentialConfig, LimitConfig, MaskingConfig, ServerConfig};

type TestError = Box<dyn Error + Send + Sync>;

const KEY_ID: &str = "e2e-client";
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const HANDSHAKE_TIMEOUT_SECONDS: u64 = 2;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

const CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
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

const KEY_PEM: &str = r"-----BEGIN PRIVATE KEY-----
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

struct TestServer {
    addr: std::net::SocketAddr,
    observability_addr: std::net::SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), TestError>>,
}

impl TestServer {
    async fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

fn create_temp_dir() -> Result<std::path::PathBuf, TestError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("uk-mask-e2e-{}-{now}-{id}", process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn restrict_private_file(path: &std::path::Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn write_identity(
    dir: &std::path::Path,
) -> Result<(std::path::PathBuf, std::path::PathBuf), TestError> {
    let cert_path = dir.join("server-cert.pem");
    let key_path = dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM)?;
    fs::write(&key_path, KEY_PEM)?;
    restrict_private_file(&key_path)?;
    Ok((cert_path, key_path))
}

fn write_policy(dir: &std::path::Path) -> Result<std::path::PathBuf, TestError> {
    let policy_path = dir.join("policy.toml");
    fs::write(
        &policy_path,
        r#"
        [[rules]]
        action = "allow"
        cidr = "127.0.0.1/32"
        private = true
        "#,
    )?;
    restrict_private_file(&policy_path)?;
    Ok(policy_path)
}

fn masked_server_config(
    listen: std::net::SocketAddr,
    observability: std::net::SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    policy_path: Option<&std::path::Path>,
) -> ServerConfig {
    masked_server_config_with_quic(
        listen,
        None,
        observability,
        cert_path,
        key_path,
        policy_path,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn masked_server_config_with_quic(
    listen: std::net::SocketAddr,
    quic_listen: Option<std::net::SocketAddr>,
    observability: std::net::SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    policy_path: Option<&std::path::Path>,
    quic_masking: bool,
) -> ServerConfig {
    ServerConfig {
        listen: listen.to_string(),
        quic_listen: quic_listen.map(|addr| addr.to_string()),
        observability_listen: Some(observability.to_string()),
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        auth_skew_seconds: Some(30),
        limits: Some(LimitConfig {
            handshake_timeout_seconds: Some(HANDSHAKE_TIMEOUT_SECONDS),
            ..LimitConfig::default()
        }),
        policy_path: policy_path.map(|path| path.display().to_string()),
        credentials: vec![CredentialConfig {
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            status: Some("active".to_owned()),
            not_before: None,
            not_after: None,
            policy_group: Some("default".to_owned()),
        }],
        masking: Some(MaskingConfig {
            enabled: Some(true),
            replay_identities: None,
            quic: Some(quic_masking),
            quic_key_id: quic_masking.then(|| KEY_ID.to_owned()),
        }),
    }
}

fn masked_client_config(
    server_addr: std::net::SocketAddr,
    cert_path: &std::path::Path,
    handshake_timeout_seconds: Option<u64>,
) -> ClientConfig {
    ClientConfig {
        server_addr: server_addr.to_string(),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: cert_path.display().to_string(),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds,
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
        masking: Some(ClientMaskingConfig {
            enabled: Some(true),
            prelude_policy: None,
            quic: None,
        }),
    }
}

/// Spawns a masked server and waits for its observability endpoint (never the
/// carrier listener: a TCP probe there would burn auth-limiter budget).
async fn spawn_masked_server(
    policy: bool,
) -> Result<(TestServer, std::path::PathBuf, std::path::PathBuf), TestError> {
    let dir = create_temp_dir()?;
    let (cert_path, key_path) = write_identity(&dir)?;
    let policy_path = if policy {
        Some(write_policy(&dir)?)
    } else {
        None
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let observability_listener = TcpListener::bind("127.0.0.1:0").await?;
    let observability_addr = observability_listener.local_addr()?;
    drop(observability_listener);
    let config = masked_server_config(
        addr,
        observability_addr,
        &cert_path,
        &key_path,
        policy_path.as_deref(),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await
        .map_err(|err| -> TestError { err.to_string().into() })
    });
    let server = TestServer {
        addr,
        observability_addr,
        shutdown: shutdown_tx,
        task,
    };
    wait_until_observability_ready(server.observability_addr).await?;
    Ok((server, cert_path, key_path))
}

async fn wait_until_observability_ready(addr: std::net::SocketAddr) -> Result<(), TestError> {
    for _ in 0..200 {
        if http_get_metrics(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("observability endpoint never became ready".into())
}

async fn http_get_metrics(addr: std::net::SocketAddr) -> Result<String, TestError> {
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

fn trusting_tls_connector(cert_path: &std::path::Path) -> Result<TlsConnector, TestError> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(cert_path)? {
        roots.add(cert?)?;
    }
    let mut config = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![uk_proto::ALPN_PROTOCOL.to_vec()];
    Ok(TlsConnector::from(std::sync::Arc::new(config)))
}

/// Opens a raw TCP connection, writes a caller-chosen prelude, and runs a real
/// TLS 1.3 handshake through the masking layer with that exact prelude.
async fn masked_tls_handshake(
    addr: std::net::SocketAddr,
    cert_path: &std::path::Path,
    keys: &MaskKeys,
    prelude: &ClientPrelude,
) -> Result<tokio_rustls::client::TlsStream<MaskedStream<TcpStream>>, TestError> {
    let mut tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
    wire[..PRELUDE_LEN].copy_from_slice(&prelude.bytes);
    wire[PRELUDE_LEN..].copy_from_slice(&prelude.nonce);
    tcp.write_all(&wire).await?;
    let masked = MaskedStream::new_client(tcp, keys, &prelude.nonce);
    let connector = trusting_tls_connector(cert_path)?;
    let stream = connector
        .connect(ServerName::try_from("localhost")?, masked)
        .await?;
    Ok(stream)
}

/// Echo target: accepts one connection and echoes every byte back.
async fn spawn_echo_target()
-> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), TestError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0_u8; 4096];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    Ok((addr, task))
}

#[tokio::test]
async fn masked_carrier_runs_a_full_authenticated_tcp_flow() -> Result<(), TestError> {
    let (server, cert_path, _key_path) = spawn_masked_server(true).await?;
    let (target_addr, target) = spawn_echo_target().await?;

    let result: Result<(), TestError> = async {
        let mut client = masked_client_config(server.addr, &cert_path, Some(10));
        client.server_addr = format!("tls://{}", server.addr);
        let (mut carrier, _settings) = connect_authenticated_carrier(client).await?;

        let open = TcpOpen::new(target_from_socket_addr(target_addr), TCP_OPEN_FLAGS_NONE);
        let mut payload = BytesMut::new();
        open.encode(&mut payload)?;
        write_frame(
            &mut carrier,
            &Frame::new(FrameType::TcpOpen, 0, 1, payload.freeze())?,
        )
        .await?;

        // Open ack: empty TCP_DATA on flow 1.
        let ack = tokio::time::timeout(
            Duration::from_secs(3),
            read_frame(&mut carrier, FrameLimits::default()),
        )
        .await??;
        assert_eq!(ack.header.frame_type, FrameType::TcpData);
        assert_eq!(ack.header.id, 1);
        assert!(ack.payload.is_empty());

        let message = b"masked-relay-payload";
        write_frame(
            &mut carrier,
            &Frame::new(FrameType::TcpData, 0, 1, bytes::Bytes::from_static(message))?,
        )
        .await?;
        let echoed = tokio::time::timeout(
            Duration::from_secs(3),
            read_frame(&mut carrier, FrameLimits::default()),
        )
        .await??;
        assert_eq!(echoed.header.frame_type, FrameType::TcpData);
        assert_eq!(echoed.header.id, 1);
        assert_eq!(&echoed.payload[..], message);
        Ok(())
    }
    .await;

    target.abort();
    server.stop().await;
    result
}

#[tokio::test]
async fn blind_garbage_probe_receives_no_bytes_and_is_counted() -> Result<(), TestError> {
    let (server, _cert_path, _key_path) = spawn_masked_server(false).await?;

    let mut probe = TcpStream::connect(server.addr).await?;
    // 76 bytes of garbage where the prelude + nonce should be.
    probe.write_all(&[0xa5_u8; PRELUDE_LEN + NONCE_LEN]).await?;

    // Before the admission deadline: zero response bytes of any kind.
    let mut buf = [0_u8; 64];
    let read = tokio::time::timeout(Duration::from_millis(500), probe.read(&mut buf)).await;
    assert!(
        read.is_err(),
        "masked server must stay silent before the admission deadline"
    );

    // The connection is drained until the deadline, then abortively closed:
    // the next read terminates (EOF or reset) instead of hanging forever.
    let closed = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS + 3),
        probe.read(&mut buf),
    )
    .await;
    assert!(closed.is_ok(), "server must close the rejected connection");

    // The rejection is visible in metrics with proper exposition.
    for _ in 0..100 {
        let metrics = http_get_metrics(server.observability_addr).await?;
        if metrics.contains("uncrowned_king_server_mask_prelude_rejects_total 1\n") {
            assert!(metrics.contains("# HELP uncrowned_king_server_mask_prelude_rejects_total"));
            assert!(
                metrics.contains("# TYPE uncrowned_king_server_mask_prelude_rejects_total counter")
            );
            server.stop().await;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    server.stop().await;
    Err("mask prelude reject counter never incremented".into())
}

/// A probe that sends only part of the prelude and keeps the connection open
/// must receive exactly the same silent treatment as a full garbage prelude:
/// zero response bytes, held through the jittered drain dwell (never closed
/// immediately), abortive close afterwards, and one rejection counted. This
/// pins the uniform rejection posture — a short read must not be
/// distinguishable from a bad prelude by timing or content.
#[tokio::test]
async fn short_prelude_probe_gets_the_same_silent_treatment() -> Result<(), TestError> {
    let (server, _cert_path, _key_path) = spawn_masked_server(false).await?;

    let mut probe = TcpStream::connect(server.addr).await?;
    // Far fewer than the 76 bytes the admission gate waits for.
    probe.write_all(&[0x5a_u8; 20]).await?;

    // No response bytes while the drain dwell runs.
    let mut buf = [0_u8; 64];
    let read = tokio::time::timeout(Duration::from_millis(500), probe.read(&mut buf)).await;
    assert!(
        read.is_err(),
        "a short-read probe must be held silently, not answered or closed at once"
    );

    // The dwell expires (bounded by the admission timeout) and the socket is
    // abortively closed.
    let closed = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS + 3),
        probe.read(&mut buf),
    )
    .await;
    assert!(closed.is_ok(), "server must close the short-read probe");

    for _ in 0..100 {
        let metrics = http_get_metrics(server.observability_addr).await?;
        if metrics.contains("uncrowned_king_server_mask_prelude_rejects_total 1\n") {
            server.stop().await;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    server.stop().await;
    Err("short-read rejection was never counted".into())
}

#[tokio::test]
async fn replayed_prelude_is_silently_rejected() -> Result<(), TestError> {
    let (server, cert_path, _key_path) = spawn_masked_server(false).await?;
    let keys = MaskKeys::derive(KEY_ID.as_bytes(), SECRET.as_bytes());
    let identity = 0x0bad_f00d_cafe_babe;
    let counter = 7;
    let prelude = keys
        .encode_prelude(
            PreludePolicy::Full8,
            &mut rand::rngs::OsRng,
            identity,
            counter,
        )
        .unwrap();
    let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
    wire[..PRELUDE_LEN].copy_from_slice(&prelude.bytes);
    wire[PRELUDE_LEN..].copy_from_slice(&prelude.nonce);

    // First copy: a complete masked TLS handshake. The counter commits at
    // the first non-alert record write (two-phase commit).
    let mut first = masked_tls_handshake(server.addr, &cert_path, &keys, &prelude).await?;
    // The server speaks first: AUTH_CHALLENGE proves the handshake completed
    // and the commit fired.
    let challenge = tokio::time::timeout(
        Duration::from_secs(3),
        uk_proto::read_frame(&mut first, FrameLimits::default()),
    )
    .await??;
    assert_eq!(challenge.header.frame_type, FrameType::AuthChallenge);

    // Second copy: identical identity + counter — replay, silently dropped.
    let mut replay = TcpStream::connect(server.addr).await?;
    replay.write_all(&wire).await?;
    let mut buf = [0_u8; 64];
    let silent = tokio::time::timeout(Duration::from_millis(500), replay.read(&mut buf)).await;
    assert!(silent.is_err(), "replayed prelude must receive no bytes");

    for _ in 0..100 {
        let metrics = http_get_metrics(server.observability_addr).await?;
        if metrics.contains("uncrowned_king_server_mask_replay_rejects_total 1\n") {
            server.stop().await;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let diagnostics = http_get_metrics(server.observability_addr)
        .await
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains("mask_"))
        .collect::<Vec<_>>()
        .join(" | ");
    server.stop().await;
    Err(format!("mask replay reject counter never incremented: {diagnostics}").into())
}

#[tokio::test]
async fn malformed_hello_does_not_burn_the_counter() -> Result<(), TestError> {
    let (server, cert_path, _key_path) = spawn_masked_server(false).await?;
    let keys = MaskKeys::derive(KEY_ID.as_bytes(), SECRET.as_bytes());
    let identity = 0xfeed_face_1234_5678;
    let counter = 21;
    let prelude = keys
        .encode_prelude(
            PreludePolicy::Full8,
            &mut rand::rngs::OsRng,
            identity,
            counter,
        )
        .unwrap();
    let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
    wire[..PRELUDE_LEN].copy_from_slice(&prelude.bytes);
    wire[PRELUDE_LEN..].copy_from_slice(&prelude.nonce);

    // First copy: valid prelude, then bytes that can never parse as TLS. The
    // server aborts without any non-alert write, so the counter stays
    // uncommitted (two-phase semantics).
    let mut garbage = TcpStream::connect(server.addr).await?;
    garbage.write_all(&wire).await?;
    let junk = [99_u8; 64]; // invalid TLS content type in the record header
    garbage.write_all(&junk).await?;
    let mut buf = [0_u8; 64];
    let closed = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS + 3),
        garbage.read(&mut buf),
    )
    .await;
    assert!(
        closed.is_ok(),
        "connection with a malformed hello must close"
    );
    let metrics = http_get_metrics(server.observability_addr).await?;
    assert!(
        !metrics.contains("uncrowned_king_server_mask_replay_rejects_total 1"),
        "garbage after a valid prelude is not a replay"
    );

    // Second copy: the SAME identity + counter now completes a real masked
    // TLS handshake — proving the malformed hello did not burn the counter.
    let mut second = masked_tls_handshake(server.addr, &cert_path, &keys, &prelude).await?;
    let challenge = tokio::time::timeout(
        Duration::from_secs(3),
        uk_proto::read_frame(&mut second, FrameLimits::default()),
    )
    .await??;
    assert_eq!(challenge.header.frame_type, FrameType::AuthChallenge);

    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn masked_client_to_unmasked_server_fails_closed() -> Result<(), TestError> {
    let dir = create_temp_dir()?;
    let (cert_path, key_path) = write_identity(&dir)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let mut config = masked_server_config(addr, addr, &cert_path, &key_path, None);
    config.masking = None;
    config.observability_listen = None;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await
        .map_err(|err| -> TestError { err.to_string().into() })
    });
    // Wait for the listener without burning limiter budget on the carrier
    // port: the observability endpoint is disabled here, so poll the binary
    // task and the port in a low-frequency loop (one probe is fine: this
    // server has no masking, so probes are ordinary TLS failures).
    let task = task;
    for _ in 0..200 {
        if task.is_finished() {
            return Err("unmasked server stopped early".into());
        }
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let client = masked_client_config(addr, &dir.join("server-cert.pem"), Some(3));
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        connect_authenticated_carrier(client),
    )
    .await;
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(
        outcome.is_err() || outcome.unwrap().is_err(),
        "masked client must not authenticate against an unmasked listener"
    );
    Ok(())
}

#[tokio::test]
async fn unmasked_client_to_masked_server_times_out() -> Result<(), TestError> {
    let (server, cert_path, _key_path) = spawn_masked_server(false).await?;

    let mut client = masked_client_config(server.addr, &cert_path, Some(2));
    client.masking = None; // plain TLS client against a masked listener
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        connect_authenticated_carrier(client),
    )
    .await;

    server.stop().await;
    assert!(
        outcome.is_err() || outcome.unwrap().is_err(),
        "unmasked client must fail against a masked listener (silent drain, no TLS bytes)"
    );
    Ok(())
}

#[tokio::test]
async fn masked_quic_carrier_runs_a_full_authenticated_tcp_flow() -> Result<(), TestError> {
    let dir = create_temp_dir()?;
    let (cert_path, key_path) = write_identity(&dir)?;
    let policy_path = write_policy(&dir)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let quic_listener = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let quic_addr = quic_listener.local_addr()?;
    drop(quic_listener);
    let observability_listener = TcpListener::bind("127.0.0.1:0").await?;
    let observability_addr = observability_listener.local_addr()?;
    drop(observability_listener);
    let config = masked_server_config_with_quic(
        addr,
        Some(quic_addr),
        observability_addr,
        &cert_path,
        &key_path,
        Some(&policy_path),
        true,
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });
    // Wait for readiness via the unauthenticated metrics port (never probe
    // the carrier: a masked QUIC listener drops everything silently).
    let mut ready = false;
    for _ in 0..200 {
        if http_get_metrics(observability_addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if !ready {
        shutdown_tx.send(()).ok();
        return Err("masked QUIC server never became ready".into());
    }

    let (target_addr, target) = spawn_echo_target().await?;

    let result: Result<(), TestError> = async {
        let mut client = masked_client_config(quic_addr, &cert_path, Some(10));
        client.server_addr = format!("quic://{quic_addr}");
        client.masking.as_mut().unwrap().quic = Some(true);
        let (mut carrier, _settings) = connect_authenticated_carrier(client).await?;

        let open = TcpOpen::new(target_from_socket_addr(target_addr), TCP_OPEN_FLAGS_NONE);
        let mut payload = BytesMut::new();
        open.encode(&mut payload)?;
        write_frame(
            &mut carrier,
            &Frame::new(FrameType::TcpOpen, 0, 1, payload.freeze())?,
        )
        .await?;
        let ack = tokio::time::timeout(
            Duration::from_secs(3),
            read_frame(&mut carrier, FrameLimits::default()),
        )
        .await??;
        assert_eq!(ack.header.frame_type, FrameType::TcpData);
        assert_eq!(ack.header.id, 1);
        assert!(ack.payload.is_empty());

        let message = b"masked-quic-relay-payload";
        write_frame(
            &mut carrier,
            &Frame::new(FrameType::TcpData, 0, 1, bytes::Bytes::from_static(message))?,
        )
        .await?;
        let echoed = tokio::time::timeout(
            Duration::from_secs(3),
            read_frame(&mut carrier, FrameLimits::default()),
        )
        .await??;
        assert_eq!(echoed.header.frame_type, FrameType::TcpData);
        assert_eq!(echoed.header.id, 1);
        assert_eq!(&echoed.payload[..], message);
        Ok(())
    }
    .await;

    target.abort();
    shutdown_tx.send(()).ok();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    result
}

#[tokio::test]
async fn unmasked_quic_client_cannot_talk_to_masked_quic_listener() -> Result<(), TestError> {
    let dir = create_temp_dir()?;
    let (cert_path, key_path) = write_identity(&dir)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let observability_listener = TcpListener::bind("127.0.0.1:0").await?;
    let observability_addr = observability_listener.local_addr()?;
    drop(observability_listener);
    let quic_listener = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let quic_addr = quic_listener.local_addr()?;
    drop(quic_listener);
    let config = masked_server_config_with_quic(
        addr,
        Some(quic_addr),
        observability_addr,
        &cert_path,
        &key_path,
        None,
        true,
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await
        .map_err(|err| -> TestError { err.to_string().into() })
    });
    wait_until_observability_ready(observability_addr).await?;

    let client_config_base = masked_client_config(quic_addr, &cert_path, Some(2));
    let mut client = client_config_base;
    client.server_addr = format!("quic://{quic_addr}");
    client.masking = None; // plain QUIC against a masked listener
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        connect_authenticated_carrier(client),
    )
    .await;
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(
        outcome.is_err() || outcome.unwrap().is_err(),
        "unmasked QUIC client must fail against a masked listener"
    );
    Ok(())
}

async fn spawn_custom_server(
    mut config: ServerConfig,
) -> Result<(TestServer, std::path::PathBuf), TestError> {
    let dir = create_temp_dir()?;
    let (cert_path, key_path) = write_identity(&dir)?;
    let policy_path = write_policy(&dir)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let observability_listener = TcpListener::bind("127.0.0.1:0").await?;
    let observability_addr = observability_listener.local_addr()?;
    drop(observability_listener);

    config.listen = addr.to_string();
    config.observability_listen = Some(observability_addr.to_string());
    config.cert_path = cert_path.display().to_string();
    config.key_path = key_path.display().to_string();
    config.policy_path = Some(policy_path.display().to_string());

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await
        .map_err(|err| -> TestError { err.to_string().into() })
    });
    let server = TestServer {
        addr,
        observability_addr,
        shutdown: shutdown_tx,
        task,
    };
    wait_until_observability_ready(server.observability_addr).await?;
    Ok((server, cert_path))
}

async fn wait_for_metric_substring(
    addr: std::net::SocketAddr,
    needle: &str,
    timeout: Duration,
) -> Result<String, TestError> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Ok(metrics) = http_get_metrics(addr).await
                && metrics.contains(needle)
            {
                return metrics;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| -> TestError { format!("timed out waiting for metric `{needle}`").into() })
}

async fn assert_echo_works(
    mut carrier: uk_client::ClientCarrier,
    payload_bytes: &[u8],
    target_addr: std::net::SocketAddr,
) -> Result<(), TestError> {
    let open = TcpOpen::new(target_from_socket_addr(target_addr), TCP_OPEN_FLAGS_NONE);
    let mut payload = BytesMut::new();
    open.encode(&mut payload)?;
    write_frame(
        &mut carrier,
        &Frame::new(FrameType::TcpOpen, 0, 1, payload.freeze())?,
    )
    .await?;
    let ack = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(ack.header.frame_type, FrameType::TcpData);
    assert!(ack.payload.is_empty());

    write_frame(
        &mut carrier,
        &Frame::new(
            FrameType::TcpData,
            0,
            1,
            bytes::Bytes::copy_from_slice(payload_bytes),
        )?,
    )
    .await?;
    let echoed = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(&echoed.payload[..], payload_bytes);
    Ok(())
}

struct RecordingTcp {
    inner: TcpStream,
    bytes_read: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl tokio::io::AsyncRead for RecordingTcp {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &poll {
            let delta = buf.filled().len().saturating_sub(before);
            self.bytes_read.fetch_add(delta, Ordering::Relaxed);
        }
        poll
    }
}

impl tokio::io::AsyncWrite for RecordingTcp {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl uk_mask::stream::WriteReady for RecordingTcp {
    fn poll_write_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        self.inner.poll_write_ready(cx)
    }
}

#[tokio::test]
async fn masked_corrupted_and_alert_hellos_emit_zero_bytes_and_trigger_rate_limiter()
-> Result<(), TestError> {
    let mut cfg = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    cfg.limits = Some(LimitConfig {
        handshake_timeout_seconds: Some(1),
        auth_rate_limit_failures: Some(2),
        auth_rate_limit_window_seconds: Some(60),
        auth_rate_limit_ban_seconds: Some(60),
        ..LimitConfig::default()
    });
    let (server, cert_path) = spawn_custom_server(cfg).await?;
    let keys = MaskKeys::derive(KEY_ID.as_bytes(), SECRET.as_bytes());
    let prelude = keys
        .encode_prelude(PreludePolicy::Full8, &mut rand::rngs::OsRng, 0x1001, 1)
        .unwrap();

    // Probe 1: valid prelude + malformed ClientHello triggering Acceptor alert.
    let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
    wire[..PRELUDE_LEN].copy_from_slice(&prelude.bytes);
    wire[PRELUDE_LEN..].copy_from_slice(&prelude.nonce);

    let mut tcp1 = TcpStream::connect(server.addr).await?;
    tcp1.write_all(&wire).await?;
    let mut masked1 = MaskedStream::new_client(tcp1, &keys, &prelude.nonce);
    // TLS Handshake record with malformed ClientHello body (triggers alert in rustls::server::Acceptor).
    masked1
        .write_all(&[22_u8, 3, 1, 0, 5, 1, 0, 0, 1, 0xff])
        .await?;
    masked1.flush().await?;
    let mut resp1 = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), masked1.read_to_end(&mut resp1)).await?;
    assert!(resp1.is_empty(), "server must emit 0 bytes on TLS alert");

    let metrics = wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_handshake_failures_total{reason=\"tls\"} 1\n",
        Duration::from_secs(3),
    )
    .await?;
    assert!(metrics.contains("uncrowned_king_server_mask_replay_rejects_total 0\n"));

    // Probe 2: reuse the SAME prelude (proving counter was not burned), send truncated invalid record.
    let mut tcp2 = TcpStream::connect(server.addr).await?;
    tcp2.write_all(&wire).await?;
    let mut masked2 = MaskedStream::new_client(tcp2, &keys, &prelude.nonce);
    masked2.write_all(&[22_u8, 3, 3, 0, 4, 0, 0, 0, 0]).await?;
    masked2.flush().await?;
    let mut resp2 = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), masked2.read_to_end(&mut resp2)).await?;
    assert!(
        resp2.is_empty(),
        "server must emit 0 bytes on corrupted hello"
    );

    wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_handshake_failures_total{reason=\"tls\"} 2\n",
        Duration::from_secs(3),
    )
    .await?;

    // Probe 3: IP is now banned after 2 pre-ClientHello failures.
    let mut client = masked_client_config(server.addr, &cert_path, Some(2));
    client.server_addr = format!("tls://{}", server.addr);
    let banned_res = tokio::time::timeout(
        Duration::from_secs(3),
        connect_authenticated_carrier(client),
    )
    .await;
    assert!(
        banned_res.is_ok() && banned_res.unwrap().is_err(),
        "banned source must be rejected immediately"
    );
    wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_rate_limited_connections_total 1\n",
        Duration::from_secs(3),
    )
    .await?;

    server.stop().await;
    Ok(())
}

fn build_test_client_hello(
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<Vec<u8>, TestError> {
    let mut cfg = RustlsClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)?
    .with_root_certificates(RootCertStore::empty())
    .with_no_client_auth();
    cfg.alpn_protocols = alpn_protocols;
    let mut conn = rustls::ClientConnection::new(
        std::sync::Arc::new(cfg),
        ServerName::try_from("localhost")?,
    )?;
    let mut hello = Vec::new();
    conn.write_tls(&mut hello)?;
    Ok(hello)
}

#[tokio::test]
async fn masked_tls12_and_alpn_mismatch_client_hellos_emit_zero_bytes_preserve_counter_and_rate_limit()
-> Result<(), TestError> {
    let mut cfg = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    cfg.limits = Some(LimitConfig {
        handshake_timeout_seconds: Some(1),
        auth_rate_limit_failures: Some(2),
        auth_rate_limit_window_seconds: Some(60),
        auth_rate_limit_ban_seconds: Some(60),
        ..LimitConfig::default()
    });
    let (server, cert_path) = spawn_custom_server(cfg).await?;
    let keys = MaskKeys::derive(KEY_ID.as_bytes(), SECRET.as_bytes());
    let prelude = keys
        .encode_prelude(PreludePolicy::Full8, &mut rand::rngs::OsRng, 0x3001, 1)
        .unwrap();

    let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
    wire[..PRELUDE_LEN].copy_from_slice(&prelude.bytes);
    wire[PRELUDE_LEN..].copy_from_slice(&prelude.nonce);

    // Probe 1: valid 76B prelude + syntactically valid TLS 1.2-only ClientHello.
    let tls12_hello = build_test_client_hello(
        &[&rustls::version::TLS12],
        vec![uk_proto::ALPN_PROTOCOL.to_vec()],
    )?;
    let tcp1 = TcpStream::connect(server.addr).await?;
    let mut tcp1 = tcp1;
    tcp1.write_all(&wire).await?;
    let mut masked1 = MaskedStream::new_client(tcp1, &keys, &prelude.nonce);
    masked1.write_all(&tls12_hello).await?;
    masked1.flush().await?;
    let mut resp1 = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), masked1.read_to_end(&mut resp1)).await?;
    assert!(
        resp1.is_empty(),
        "server must emit 0 bytes on TLS 1.2-only ClientHello"
    );

    let metrics = wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_handshake_failures_total{reason=\"tls\"} 1\n",
        Duration::from_secs(3),
    )
    .await?;
    assert!(metrics.contains("uncrowned_king_server_mask_replay_rejects_total 0\n"));

    // Probe 2: reuse the SAME (identity, counter) prelude + TLS 1.3 ClientHello with wrong ALPN.
    let wrong_alpn_hello =
        build_test_client_hello(&[&rustls::version::TLS13], vec![b"h2".to_vec()])?;
    let mut tcp2 = TcpStream::connect(server.addr).await?;
    tcp2.write_all(&wire).await?;
    let mut masked2 = MaskedStream::new_client(tcp2, &keys, &prelude.nonce);
    masked2.write_all(&wrong_alpn_hello).await?;
    masked2.flush().await?;
    let mut resp2 = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), masked2.read_to_end(&mut resp2)).await?;
    assert!(
        resp2.is_empty(),
        "server must emit 0 bytes on wrong-ALPN ClientHello"
    );

    let metrics2 = wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_handshake_failures_total{reason=\"tls\"} 2\n",
        Duration::from_secs(3),
    )
    .await?;
    assert!(metrics2.contains("uncrowned_king_server_mask_replay_rejects_total 0\n"));

    // Probe 3: IP is now banned after 2 ServerConfig-rejected ClientHellos.
    let mut client = masked_client_config(server.addr, &cert_path, Some(2));
    client.server_addr = format!("tls://{}", server.addr);
    let banned_res = tokio::time::timeout(
        Duration::from_secs(3),
        connect_authenticated_carrier(client),
    )
    .await;
    assert!(
        banned_res.is_ok() && banned_res.unwrap().is_err(),
        "banned source must be rejected immediately"
    );
    wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_rate_limited_connections_total 1\n",
        Duration::from_secs(3),
    )
    .await?;

    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn masked_oversized_client_hello_rejected_silently() -> Result<(), TestError> {
    let mut cfg = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    cfg.limits = Some(LimitConfig {
        handshake_timeout_seconds: Some(1),
        ..LimitConfig::default()
    });
    let (server, cert_path) = spawn_custom_server(cfg).await?;
    let keys = MaskKeys::derive(KEY_ID.as_bytes(), SECRET.as_bytes());
    let prelude = keys
        .encode_prelude(PreludePolicy::Full8, &mut rand::rngs::OsRng, 0x2002, 1)
        .unwrap();

    let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
    wire[..PRELUDE_LEN].copy_from_slice(&prelude.bytes);
    wire[PRELUDE_LEN..].copy_from_slice(&prelude.nonce);

    let mut tcp = TcpStream::connect(server.addr).await?;
    tcp.write_all(&wire).await?;
    let mut masked = MaskedStream::new_client(tcp, &keys, &prelude.nonce);

    // Send fragmented 80,000-byte ClientHello (> 64 KiB cap).
    let mut payload = vec![0_u8; 5 * 16_384];
    payload[0] = 1;
    let total_len: u32 = 80_000;
    payload[1] = ((total_len >> 16) & 0xff) as u8;
    payload[2] = ((total_len >> 8) & 0xff) as u8;
    payload[3] = (total_len & 0xff) as u8;
    for chunk in payload.chunks(16_384) {
        let mut record = Vec::with_capacity(5 + chunk.len());
        record.push(22);
        record.extend_from_slice(&[3, 3]);
        record.extend_from_slice(&(u16::try_from(chunk.len())?).to_be_bytes());
        record.extend_from_slice(chunk);
        if masked.write_all(&record).await.is_err() {
            break;
        }
    }
    let _ = masked.flush().await;

    let mut resp = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(4), masked.read_to_end(&mut resp)).await?;
    assert!(
        resp.is_empty(),
        "oversized ClientHello must receive 0 response bytes"
    );

    let metrics = wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_handshake_failures_total{reason=\"tls\"} 1\n",
        Duration::from_secs(3),
    )
    .await?;
    assert!(metrics.contains("uncrowned_king_server_mask_replay_rejects_total 0\n"));

    // The counter was not burned, so a real handshake with the same prelude succeeds.
    let mut tls = masked_tls_handshake(server.addr, &cert_path, &keys, &prelude).await?;
    let challenge = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut tls, FrameLimits::default()),
    )
    .await??;
    assert_eq!(challenge.header.frame_type, FrameType::AuthChallenge);

    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn masked_concurrent_replay_race_commits_once_and_rejects_losers_silently()
-> Result<(), TestError> {
    let mut cfg = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    cfg.limits = Some(LimitConfig {
        handshake_timeout_seconds: Some(2),
        auth_rate_limit_failures: Some(0),
        ..LimitConfig::default()
    });
    let (server, cert_path) = spawn_custom_server(cfg).await?;
    let keys = MaskKeys::derive(KEY_ID.as_bytes(), SECRET.as_bytes());
    let prelude = keys
        .encode_prelude(PreludePolicy::Full8, &mut rand::rngs::OsRng, 0x3003, 9)
        .unwrap();

    let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
    wire[..PRELUDE_LEN].copy_from_slice(&prelude.bytes);
    wire[PRELUDE_LEN..].copy_from_slice(&prelude.nonce);

    let racers = 8_usize;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(racers));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..racers {
        let addr = server.addr;
        let cert_path = cert_path.clone();
        let keys = keys.clone();
        let nonce = prelude.nonce;
        let barrier = std::sync::Arc::clone(&barrier);
        tasks.spawn(async move {
            let mut tcp = TcpStream::connect(addr).await.unwrap();
            tcp.set_nodelay(true).unwrap();
            let bytes_read = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            barrier.wait().await;
            tcp.write_all(&wire).await.unwrap();
            let rec = RecordingTcp {
                inner: tcp,
                bytes_read: std::sync::Arc::clone(&bytes_read),
            };
            let masked = MaskedStream::new_client(rec, &keys, &nonce);
            let connector = trusting_tls_connector(&cert_path).unwrap();
            match tokio::time::timeout(
                Duration::from_secs(4),
                connector.connect(ServerName::try_from("localhost").unwrap(), masked),
            )
            .await
            {
                Ok(Ok(mut tls)) => {
                    let frame = tokio::time::timeout(
                        Duration::from_secs(3),
                        read_frame(&mut tls, FrameLimits::default()),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    assert_eq!(frame.header.frame_type, FrameType::AuthChallenge);
                    (true, bytes_read.load(Ordering::Relaxed))
                }
                _ => (false, bytes_read.load(Ordering::Relaxed)),
            }
        });
    }

    let mut winners = 0_usize;
    let mut losers_with_zero_bytes = 0_usize;
    while let Some(res) = tasks.join_next().await {
        let (won, read_bytes) = res?;
        if won {
            winners += 1;
        } else {
            assert_eq!(
                read_bytes, 0,
                "losing concurrent replay racers must receive zero wire bytes"
            );
            losers_with_zero_bytes += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one racer must commit the counter");
    assert_eq!(losers_with_zero_bytes, racers - 1);

    wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_mask_replay_rejects_total 7\n",
        Duration::from_secs(3),
    )
    .await?;

    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn masked_handshake_shares_single_deadline_across_prelude_tls_and_auth_response()
-> Result<(), TestError> {
    let mut cfg = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    cfg.limits = Some(LimitConfig {
        handshake_timeout_seconds: Some(2),
        ..LimitConfig::default()
    });
    let (server, cert_path) = spawn_custom_server(cfg).await?;
    let keys = MaskKeys::derive(KEY_ID.as_bytes(), SECRET.as_bytes());
    let prelude = keys
        .encode_prelude(PreludePolicy::Full8, &mut rand::rngs::OsRng, 0x4004, 1)
        .unwrap();

    // Complete prelude + TLS 1.3 handshake, read AUTH_CHALLENGE, then stall AUTH_RESPONSE.
    let start = std::time::Instant::now();
    let mut tls = masked_tls_handshake(server.addr, &cert_path, &keys, &prelude).await?;
    let challenge = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut tls, FrameLimits::default()),
    )
    .await??;
    assert_eq!(challenge.header.frame_type, FrameType::AuthChallenge);

    let mut buf = [0_u8; 64];
    let closed = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await;
    let elapsed = start.elapsed();
    assert!(
        closed.is_ok(),
        "stalled AUTH_RESPONSE must be closed at shared deadline"
    );
    assert!(
        elapsed < Duration::from_millis(3200),
        "masked handshake must share a single 2s deadline (not 2x = 4s); elapsed={elapsed:?}"
    );

    wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_handshake_failures_total{reason=\"timeout\"} 1\n",
        Duration::from_secs(3),
    )
    .await?;

    // Full authenticated session completes cleanly and restores normal close semantics.
    let (target_addr, target) = spawn_echo_target().await?;
    let mut client = masked_client_config(server.addr, &cert_path, Some(5));
    client.server_addr = format!("tls://{}", server.addr);
    let (carrier, _settings) = connect_authenticated_carrier(client).await?;
    assert_echo_works(carrier, b"r4-post-auth", target_addr).await?;
    wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_authenticated_sessions_total 1\n",
        Duration::from_secs(3),
    )
    .await?;

    target.abort();
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn pre_admission_enforces_global_and_per_source_limits_without_ban() -> Result<(), TestError>
{
    // Part A: per-source pre-admission limit rejects 3rd silent probe immediately without AuthRateLimiter ban.
    let mut cfg = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    cfg.limits = Some(LimitConfig {
        handshake_timeout_seconds: Some(5),
        max_pre_auth_connections: Some(3),
        max_pre_auth_per_source: Some(2),
        auth_rate_limit_failures: Some(2),
        auth_rate_limit_window_seconds: Some(60),
        auth_rate_limit_ban_seconds: Some(60),
        ..LimitConfig::default()
    });
    let (server, cert_path) = spawn_custom_server(cfg).await?;

    let held1 = TcpStream::connect(server.addr).await?;
    let held2 = TcpStream::connect(server.addr).await?;
    wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_accepted_connections_total 2\n",
        Duration::from_secs(3),
    )
    .await?;

    let mut rejected = TcpStream::connect(server.addr).await?;
    let mut buf = [0_u8; 32];
    let read = tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut buf)).await;
    assert!(
        read.is_ok() && matches!(read.unwrap(), Ok(0) | Err(_)),
        "3rd pre-auth connection must be dropped immediately (< 1s, well below 5s timeout)"
    );
    let metrics = wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_rejected_pre_auth_connections_total 1\n",
        Duration::from_secs(3),
    )
    .await?;
    assert!(
        metrics.contains("uncrowned_king_server_rate_limited_connections_total 0\n"),
        "pre-admission overflow must not trigger AuthRateLimiter"
    );
    drop(held1);
    drop(held2);
    server.stop().await;

    // Part B: authenticated sessions release their pre-auth slots so new clients still connect.
    let mut cfg2 = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    cfg2.limits = Some(LimitConfig {
        handshake_timeout_seconds: Some(5),
        max_sessions: Some(4),
        max_pre_auth_connections: Some(2),
        max_pre_auth_per_source: Some(2),
        ..LimitConfig::default()
    });
    let (server2, cert_path2) = spawn_custom_server(cfg2).await?;
    let mut client = masked_client_config(server2.addr, &cert_path2, Some(5));
    client.server_addr = format!("tls://{}", server2.addr);
    let (carrier1, _) = connect_authenticated_carrier(client.clone()).await?;
    let (carrier2, _) = connect_authenticated_carrier(client.clone()).await?;
    let (carrier3, _) = connect_authenticated_carrier(client).await?;
    drop((carrier1, carrier2, carrier3));
    let _ = cert_path;
    server2.stop().await;
    Ok(())
}

struct CountingUdpProxy {
    addr: std::net::SocketAddr,
    c2s_packets: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    s2c_lengths: std::sync::Arc<tokio::sync::Mutex<Vec<usize>>>,
    tasks: tokio::task::JoinSet<()>,
}

async fn spawn_counting_udp_proxy(
    upstream: std::net::SocketAddr,
) -> Result<CountingUdpProxy, TestError> {
    let proxy_sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let addr = proxy_sock.local_addr()?;
    let upstream_sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    upstream_sock.connect(upstream).await?;

    let c2s_packets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let s2c_lengths = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<usize>::new()));
    let client_peer: std::sync::Arc<tokio::sync::Mutex<Option<std::net::SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let mut tasks = tokio::task::JoinSet::new();
    {
        let proxy_sock = std::sync::Arc::clone(&proxy_sock);
        let upstream_sock = std::sync::Arc::clone(&upstream_sock);
        let c2s_packets = std::sync::Arc::clone(&c2s_packets);
        let client_peer = std::sync::Arc::clone(&client_peer);
        tasks.spawn(async move {
            let mut buf = [0_u8; 2048];
            while let Ok((n, peer)) = proxy_sock.recv_from(&mut buf).await {
                *client_peer.lock().await = Some(peer);
                c2s_packets.fetch_add(1, Ordering::Relaxed);
                if upstream_sock.send(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    }
    {
        let proxy_sock = std::sync::Arc::clone(&proxy_sock);
        let upstream_sock = std::sync::Arc::clone(&upstream_sock);
        let s2c_lengths = std::sync::Arc::clone(&s2c_lengths);
        let client_peer = std::sync::Arc::clone(&client_peer);
        tasks.spawn(async move {
            let mut buf = [0_u8; 2048];
            while let Ok(n) = upstream_sock.recv(&mut buf).await {
                s2c_lengths.lock().await.push(n);
                if let Some(peer) = *client_peer.lock().await {
                    let _ = proxy_sock.send_to(&buf[..n], peer).await;
                }
            }
        });
    }

    Ok(CountingUdpProxy {
        addr,
        c2s_packets,
        s2c_lengths,
        tasks,
    })
}

fn parse_metric_counter(metrics: &str, name: &str) -> usize {
    metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.trim().parse::<usize>().ok())
        })
        .unwrap_or(0)
}

#[tokio::test]
async fn masked_quic_silent_rejection_emits_zero_packets_on_overflow() -> Result<(), TestError> {
    let dir = create_temp_dir()?;
    let (cert_path, key_path) = write_identity(&dir)?;
    let policy_path = write_policy(&dir)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = listener.local_addr()?;
    let quic_probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let quic_addr = quic_probe.local_addr()?;
    drop(quic_probe);
    let obs_probe = TcpListener::bind("127.0.0.1:0").await?;
    let obs_addr = obs_probe.local_addr()?;
    drop(obs_probe);

    let mut config = masked_server_config_with_quic(
        tcp_addr,
        Some(quic_addr),
        obs_addr,
        &cert_path,
        &key_path,
        Some(&policy_path),
        true,
    );
    config.limits = Some(LimitConfig {
        max_sessions: Some(1),
        handshake_timeout_seconds: Some(1),
        ..LimitConfig::default()
    });
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let _ = uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });
    wait_until_observability_ready(obs_addr).await?;

    // Occupy the single session permit with a live masked QUIC carrier.
    let mut client1 = masked_client_config(quic_addr, &cert_path, Some(5));
    client1.server_addr = format!("quic://{quic_addr}");
    client1.masking.as_mut().unwrap().quic = Some(true);
    let (_held_carrier, _) = connect_authenticated_carrier(client1).await?;

    let retries_before = parse_metric_counter(
        &http_get_metrics(obs_addr).await?,
        "uncrowned_king_server_quic_retries_total ",
    );

    // Interpose a UDP forwarder to count C2S vs S2C packets for the 2nd QUIC client.
    let mut proxy = spawn_counting_udp_proxy(quic_addr).await?;

    let mut client2 = masked_client_config(proxy.addr, &cert_path, Some(1));
    client2.server_addr = format!("quic://{}", proxy.addr);
    client2.masking.as_mut().unwrap().quic = Some(true);
    let res2 = tokio::time::timeout(
        Duration::from_secs(3),
        connect_authenticated_carrier(client2),
    )
    .await;
    let err2 = match &res2 {
        Ok(Err(err)) => err.to_string(),
        Err(_) => "timeout".to_owned(),
        Ok(Ok(_)) => "unexpected ok".to_owned(),
    };
    assert!(
        matches!(&res2, Ok(Err(_)) | Err(_)),
        "over-limit masked QUIC client must fail"
    );

    proxy.tasks.abort_all();
    while proxy.tasks.join_next().await.is_some() {}

    let c2s = proxy.c2s_packets.load(Ordering::Relaxed);
    let s2c_lens = proxy.s2c_lengths.lock().await.clone();
    let metrics_snapshot = http_get_metrics(obs_addr).await?;
    let retries_after = parse_metric_counter(
        &metrics_snapshot,
        "uncrowned_king_server_quic_retries_total ",
    );
    let rejected_sessions = parse_metric_counter(
        &metrics_snapshot,
        "uncrowned_king_server_rejected_sessions_total ",
    );
    let retries_delta = retries_after.saturating_sub(retries_before);
    assert!(
        c2s >= 2,
        "client must have sent initial + retried packets (got {c2s})"
    );
    assert!(
        rejected_sessions >= 1,
        "over-limit QUIC attempt must reach admit_precheck and record rejected_sessions_total"
    );
    assert!(
        !err2.contains("refused") && !err2.contains("Connection lost"),
        "masked QUIC rejection must drop silently (timeout), never send CONNECTION_CLOSE: {err2}"
    );
    assert_eq!(
        s2c_lens.len(),
        retries_delta,
        "masked QUIC rejection must emit zero non-Retry S2C packets (s2c={s2c_lens:?}, retries_delta={retries_delta}, err2={err2})"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test]
async fn empty_masking_table_accepts_unmasked_tcp_flow() -> Result<(), TestError> {
    let mut cfg = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    // Equivalent to empty `[masking]` table in examples/server.toml
    cfg.masking = Some(MaskingConfig::default());
    let (server, cert_path) = spawn_custom_server(cfg).await?;
    let (target_addr, target) = spawn_echo_target().await?;

    let mut unmasked_client = masked_client_config(server.addr, &cert_path, Some(5));
    unmasked_client.server_addr = format!("tls://{}", server.addr);
    unmasked_client.masking = None;
    let (carrier, _) = connect_authenticated_carrier(unmasked_client).await?;
    assert_echo_works(carrier, b"empty-masking-unmasked-ok", target_addr).await?;

    let mut masked_client = masked_client_config(server.addr, &cert_path, Some(2));
    masked_client.server_addr = format!("tls://{}", server.addr);
    let masked_res = tokio::time::timeout(
        Duration::from_secs(4),
        connect_authenticated_carrier(masked_client),
    )
    .await;
    assert!(
        masked_res.is_err() || masked_res.unwrap().is_err(),
        "masked client must fail when [masking] has enabled unset"
    );

    target.abort();
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn split_mode_tcp_unmasked_and_quic_masked() -> Result<(), TestError> {
    let dir = create_temp_dir()?;
    let (cert_path, key_path) = write_identity(&dir)?;
    let policy_path = write_policy(&dir)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = listener.local_addr()?;
    let quic_probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let quic_addr = quic_probe.local_addr()?;
    drop(quic_probe);
    let obs_probe = TcpListener::bind("127.0.0.1:0").await?;
    let obs_addr = obs_probe.local_addr()?;
    drop(obs_probe);

    let mut config = masked_server_config_with_quic(
        tcp_addr,
        Some(quic_addr),
        obs_addr,
        &cert_path,
        &key_path,
        Some(&policy_path),
        true,
    );
    // Split mode: TCP unmasked, QUIC masked.
    config.masking.as_mut().unwrap().enabled = Some(false);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let _ = uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });
    wait_until_observability_ready(obs_addr).await?;
    let (target_addr1, target1) = spawn_echo_target().await?;
    let (target_addr2, target2) = spawn_echo_target().await?;

    // Unmasked TCP succeeds.
    let mut tcp_unmasked = masked_client_config(tcp_addr, &cert_path, Some(5));
    tcp_unmasked.server_addr = format!("tls://{tcp_addr}");
    tcp_unmasked.masking = None;
    let (tcp_carrier, _) = connect_authenticated_carrier(tcp_unmasked).await?;
    assert_echo_works(tcp_carrier, b"split-tcp-unmasked", target_addr1).await?;

    // Masked QUIC succeeds.
    let mut quic_masked = masked_client_config(quic_addr, &cert_path, Some(5));
    quic_masked.server_addr = format!("quic://{quic_addr}");
    quic_masked.masking.as_mut().unwrap().quic = Some(true);
    let (quic_carrier, _) = connect_authenticated_carrier(quic_masked).await?;
    assert_echo_works(quic_carrier, b"split-quic-masked", target_addr2).await?;

    // Masked TCP fails.
    let mut tcp_masked = masked_client_config(tcp_addr, &cert_path, Some(2));
    tcp_masked.server_addr = format!("tls://{tcp_addr}");
    let masked_res = tokio::time::timeout(
        Duration::from_secs(4),
        connect_authenticated_carrier(tcp_masked),
    )
    .await;
    assert!(
        masked_res.is_err() || masked_res.unwrap().is_err(),
        "masked TCP client must fail in split mode (enabled=false, quic=true)"
    );

    target1.abort();
    target2.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test]
async fn zero_handshake_timeout_with_masking_uses_nonzero_fallback_dwell() -> Result<(), TestError>
{
    let mut cfg = masked_server_config(
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::path::Path::new("unused"),
        std::path::Path::new("unused"),
        None,
    );
    cfg.limits = Some(LimitConfig {
        handshake_timeout_seconds: Some(0),
        ..LimitConfig::default()
    });
    let (server, cert_path) = spawn_custom_server(cfg).await?;
    let (target_addr, target) = spawn_echo_target().await?;

    // Valid masked client connects cleanly despite handshake_timeout_seconds = 0.
    let mut client = masked_client_config(server.addr, &cert_path, Some(5));
    client.server_addr = format!("tls://{}", server.addr);
    let (carrier, _) = connect_authenticated_carrier(client).await?;
    assert_echo_works(carrier, b"zero-timeout-fallback", target_addr).await?;

    // 76-byte garbage probe must dwell for [5s, 10s] (never close instantly!).
    let mut probe = TcpStream::connect(server.addr).await?;
    probe.write_all(&[0xa5_u8; PRELUDE_LEN + NONCE_LEN]).await?;
    let mut buf = [0_u8; 64];
    let early = tokio::time::timeout(Duration::from_secs(4), probe.read(&mut buf)).await;
    assert!(
        early.is_err(),
        "handshake_timeout_seconds = 0 with TCP masking must use 10s fallback dwell (>= 5s), not instant close"
    );

    let closed = tokio::time::timeout(Duration::from_secs(9), probe.read(&mut buf)).await;
    assert!(
        closed.is_ok(),
        "probe must close within 10s fallback window"
    );

    wait_for_metric_substring(
        server.observability_addr,
        "uncrowned_king_server_mask_prelude_rejects_total 1\n",
        Duration::from_secs(3),
    )
    .await?;

    target.abort();
    server.stop().await;
    Ok(())
}
