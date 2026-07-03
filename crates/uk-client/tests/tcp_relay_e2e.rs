//! End-to-end TCP relay tests.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use uk_client::{config::ClientConfig, run_socks5_listener};
use uk_server::config::{CredentialConfig, LimitConfig, ServerConfig};

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

const KEY_ID: &str = "e2e-client";
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REPLY_NOT_ALLOWED: u8 = 0x02;
const SOCKS_REPLY_HOST_UNREACHABLE: u8 = 0x04;
const HALF_CLOSE_REQUEST: &[u8] = b"uncrowned king half-close request";
const HALF_CLOSE_RESPONSE: &[u8] = b"uncrowned king half-close response";
const TARGET_HALF_CLOSE_GREETING: &[u8] = b"uncrowned king target half-close greeting";
const TARGET_HALF_CLOSE_LATE_REQUEST: &[u8] = b"uncrowned king target half-close late request";
const LARGE_PAYLOAD_LEN: usize = 128 * 1024 + 123;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

type TestError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_tcp_through_socks5_to_echo_target() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_tcp_relay_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maps_policy_denied_to_socks_not_allowed() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_policy_denied_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maps_target_unavailable_to_socks_host_unreachable() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_target_unavailable_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_domain_socks_target_to_echo_target() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_domain_relay_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preserves_client_half_close_until_target_response() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_half_close_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preserves_client_writes_after_target_half_close() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_target_half_close_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maps_stream_limit_to_socks_general_failure() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_stream_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_large_payload_across_frames() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_large_payload_e2e()).await?
}

async fn run_tcp_relay_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(b"uncrowned king e2e").await?;
    let mut echoed = vec![0_u8; "uncrowned king e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"uncrowned king e2e");

    echo_task.await??;
    Ok(())
}

async fn run_policy_denied_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = RelayHarness::start(None).await?;
    let denied_target = unused_loopback_addr().await?;
    let (_socks, connect_reply) = open_socks_connect(harness.socks_addr, denied_target).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_NOT_ALLOWED);
    Ok(())
}

async fn run_large_payload_e2e() -> Result<(), TestError> {
    init_tracing();

    let payload = large_payload();
    let (target_addr, target_task) = spawn_fixed_size_echo_target(payload.len()).await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(&payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, payload);

    target_task.await??;
    Ok(())
}

async fn run_half_close_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) =
        spawn_read_to_eof_then_respond_target(HALF_CLOSE_RESPONSE).await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(HALF_CLOSE_REQUEST).await?;
    socks.shutdown().await?;

    let mut response = vec![0_u8; HALF_CLOSE_RESPONSE.len()];
    socks.read_exact(&mut response).await?;
    assert_eq!(response, HALF_CLOSE_RESPONSE);
    let mut eof = [0_u8; 1];
    assert_eq!(socks.read(&mut eof).await?, 0);

    let target_received = target_task.await??;
    assert_eq!(target_received, HALF_CLOSE_REQUEST);
    Ok(())
}

async fn run_stream_limit_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_read_to_eof_target().await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_max_streams(1),
    )
    .await?;

    let (mut first_socks, first_reply) =
        open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(first_reply[1], SOCKS_REPLY_SUCCEEDED);

    let (_second_socks, second_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(second_reply[1], SOCKS_REPLY_GENERAL_FAILURE);

    first_socks.write_all(b"x").await?;
    first_socks.shutdown().await?;
    let target_received = target_task.await??;
    assert_eq!(target_received, b"x");
    Ok(())
}

async fn run_target_half_close_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) =
        spawn_write_shutdown_then_read_target(TARGET_HALF_CLOSE_GREETING).await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    let mut greeting = vec![0_u8; TARGET_HALF_CLOSE_GREETING.len()];
    socks.read_exact(&mut greeting).await?;
    assert_eq!(greeting, TARGET_HALF_CLOSE_GREETING);
    let mut eof = [0_u8; 1];
    assert_eq!(socks.read(&mut eof).await?, 0);

    socks.write_all(TARGET_HALF_CLOSE_LATE_REQUEST).await?;
    socks.shutdown().await?;

    let target_received = target_task.await??;
    assert_eq!(target_received, TARGET_HALF_CLOSE_LATE_REQUEST);
    Ok(())
}

async fn run_domain_relay_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_localhost_echo_target().await?;
    let harness =
        RelayHarness::start(Some(allow_localhost_domain_policy(target_addr.port()))).await?;

    let (mut socks, connect_reply) =
        open_socks_connect_domain(harness.socks_addr, "localhost", target_addr.port()).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(b"uncrowned king domain e2e").await?;
    let mut echoed = vec![0_u8; "uncrowned king domain e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"uncrowned king domain e2e");

    echo_task.await??;
    Ok(())
}

async fn run_target_unavailable_e2e() -> Result<(), TestError> {
    init_tracing();

    let unavailable_target = unused_loopback_addr().await?;
    let harness =
        RelayHarness::start(Some(allow_loopback_policy(unavailable_target.port()))).await?;
    let (_socks, connect_reply) =
        open_socks_connect(harness.socks_addr, unavailable_target).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_HOST_UNREACHABLE);
    Ok(())
}

struct RelayHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    server_task: JoinHandle<Result<(), TestError>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

impl RelayHarness {
    async fn start(policy_toml: Option<String>) -> Result<Self, TestError> {
        Self::start_with_limits(policy_toml, test_limits()).await
    }

    async fn start_with_limits(
        policy_toml: Option<String>,
        limits: LimitConfig,
    ) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        fs::write(&key_path, KEY_PEM)?;

        let policy_path = if let Some(policy_toml) = policy_toml {
            let policy_path = temp_dir.join("policy.toml");
            fs::write(&policy_path, policy_toml)?;
            Some(policy_path)
        } else {
            None
        };

        let server_addr = unused_loopback_addr().await?;
        let socks_addr = unused_loopback_addr().await?;
        let mut server_task = tokio::spawn(uk_server::run(ServerConfig {
            listen: server_addr.to_string(),
            cert_path: path_string(&cert_path),
            key_path: path_string(&key_path),
            auth_skew_seconds: Some(30),
            limits: Some(limits),
            policy_path: policy_path.as_deref().map(path_string),
            credentials: vec![CredentialConfig {
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                status: Some("active".to_owned()),
                not_before: None,
                not_after: None,
                policy_group: Some("default".to_owned()),
            }],
        }));
        wait_for_listener("uk-server", server_addr, &mut server_task).await?;

        let mut client_task = tokio::spawn(run_socks5_listener(
            ClientConfig {
                server_addr: server_addr.to_string(),
                server_name: "localhost".to_owned(),
                ca_cert_path: path_string(&cert_path),
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                handshake_timeout_seconds: Some(3),
                socks_handshake_timeout_seconds: Some(3),
                tcp_open_timeout_seconds: Some(3),
            },
            socks_addr.to_string(),
        ));
        wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

        Ok(Self {
            temp_dir,
            socks_addr,
            server_task,
            client_task,
        })
    }
}

impl Drop for RelayHarness {
    fn drop(&mut self) {
        self.client_task.abort();
        self.server_task.abort();
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

async fn spawn_echo_target()
-> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0_u8; 1024];
        let read = stream.read(&mut buf).await?;
        stream.write_all(&buf[..read]).await?;
        Ok(())
    });
    Ok((addr, task))
}

async fn spawn_fixed_size_echo_target(
    expected_len: usize,
) -> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0_u8; expected_len];
        stream.read_exact(&mut buf).await?;
        stream.write_all(&buf).await?;
        Ok(())
    });
    Ok((addr, task))
}

async fn spawn_read_to_eof_target() -> Result<
    (
        SocketAddr,
        tokio::task::JoinHandle<Result<Vec<u8>, TestError>>,
    ),
    TestError,
> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        Ok(received)
    });
    Ok((addr, task))
}

async fn spawn_write_shutdown_then_read_target(
    greeting: &'static [u8],
) -> Result<
    (
        SocketAddr,
        tokio::task::JoinHandle<Result<Vec<u8>, TestError>>,
    ),
    TestError,
> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        stream.write_all(greeting).await?;
        stream.shutdown().await?;

        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        Ok(received)
    });
    Ok((addr, task))
}

async fn spawn_read_to_eof_then_respond_target(
    response: &'static [u8],
) -> Result<
    (
        SocketAddr,
        tokio::task::JoinHandle<Result<Vec<u8>, TestError>>,
    ),
    TestError,
> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        stream.write_all(response).await?;
        stream.shutdown().await?;
        Ok(received)
    });
    Ok((addr, task))
}

async fn spawn_localhost_echo_target()
-> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let listener = TcpListener::bind(("localhost", 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0_u8; 1024];
        let read = stream.read(&mut buf).await?;
        stream.write_all(&buf[..read]).await?;
        Ok(())
    });
    Ok((addr, task))
}

async fn wait_for_listener(
    name: &str,
    addr: SocketAddr,
    task: &mut JoinHandle<Result<(), TestError>>,
) -> Result<(), TestError> {
    for _ in 0..100 {
        if task.is_finished() {
            match task.await? {
                Ok(()) => return Err(format!("{name} stopped before listening at {addr}").into()),
                Err(err) => {
                    return Err(format!("{name} failed before listening at {addr}: {err}").into());
                }
            }
        }
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("listener did not start at {addr}").into())
}

async fn open_socks_connect(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
) -> Result<(TcpStream, [u8; 10]), TestError> {
    let SocketAddr::V4(target_addr) = target_addr else {
        return Err("e2e tests only support IPv4 targets".into());
    };
    let octets = target_addr.ip().octets();
    let port = target_addr.port();
    let mut socks = TcpStream::connect(socks_addr).await?;
    socks
        .write_all(&[
            0x05,
            0x01,
            0x00,
            0x05,
            0x01,
            0x00,
            0x01,
            octets[0],
            octets[1],
            octets[2],
            octets[3],
            (port >> 8) as u8,
            port as u8,
        ])
        .await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    let mut connect_reply = [0_u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    Ok((socks, connect_reply))
}

async fn open_socks_connect_domain(
    socks_addr: SocketAddr,
    domain: &str,
    port: u16,
) -> Result<(TcpStream, [u8; 10]), TestError> {
    let domain_len = u8::try_from(domain.len())?;
    let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, domain_len];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&[(port >> 8) as u8, port as u8]);

    let mut socks = TcpStream::connect(socks_addr).await?;
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    let mut connect_reply = [0_u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    Ok((socks, connect_reply))
}

async fn unused_loopback_addr() -> Result<SocketAddr, TestError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn test_limits() -> LimitConfig {
    LimitConfig {
        max_pre_auth_bytes: Some(4096),
        max_frame_size: Some(65_536),
        max_streams: Some(8),
        idle_timeout_seconds: Some(30),
        max_buffered_bytes_per_flow: Some(1024 * 1024),
        handshake_timeout_seconds: Some(3),
        target_connect_timeout_seconds: Some(3),
        tcp_half_close_timeout_seconds: Some(3),
    }
}

fn test_limits_with_max_streams(max_streams: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.max_streams = Some(max_streams);
    limits
}

fn large_payload() -> Vec<u8> {
    (0..LARGE_PAYLOAD_LEN)
        .map(|index| (index % 251) as u8)
        .collect()
}

fn create_temp_dir() -> Result<PathBuf, TestError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("uk-e2e-{}-{now}-{id}", process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn allow_loopback_policy(port: u16) -> String {
    format!(
        r#"
        [[rules]]
        action = "allow"
        cidr = "127.0.0.1/32"
        port_start = {port}
        port_end = {port}
        "#
    )
}

fn allow_localhost_domain_policy(port: u16) -> String {
    format!(
        r#"
        [[rules]]
        action = "allow"
        domain = "localhost"
        port_start = {port}
        port_end = {port}
        "#
    )
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}
