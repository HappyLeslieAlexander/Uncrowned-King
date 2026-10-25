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
    let quic_listener = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let quic_addr = quic_listener.local_addr()?;
    drop(quic_listener);
    let mut config = masked_server_config_with_quic(
        addr,
        Some(quic_addr),
        addr,
        &cert_path,
        &key_path,
        None,
        true,
    );
    config.observability_listen = None;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await
        .map_err(|err| -> TestError { err.to_string().into() })
    });
    // Wait for the QUIC port via the task + a short settle delay; probing a
    // masked UDP listener yields nothing by design.
    for _ in 0..200 {
        if task.is_finished() {
            return Err("masked QUIC server stopped early".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

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
