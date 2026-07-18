//! End-to-end TCP and UDP relay tests.

use std::{
    fs, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use bytes::{Bytes, BytesMut};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use socket2::Socket;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Barrier, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream,
    server::TlsStream as ServerTlsStream,
};
use uk_auth::{
    AuthChallenge, AuthResponse, Credential, EXPORTER_LABEL, ReplayCache, unix_now,
    verify_auth_response,
};
use uk_client::{
    ClientReloadError, ClientReloadHandle, client_reload_channel, config::ClientConfig,
    connect_authenticated_carrier, run_handshake, run_socks5_listener_on_until_shutdown,
    run_socks5_listener_on_until_shutdown_with_reload,
};
use uk_proto::{
    ALPN_PROTOCOL, ErrorCode, ErrorPayload, Frame, FrameHeader, FrameIoError, FrameLimits,
    FrameType, SettingKey, Settings, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE,
    Target, TcpClose, TcpOpen, UDP_CLOSE_ERROR, UDP_CLOSE_NORMAL, UdpClose, UdpOpen, read_frame,
    validate_connection_frame, write_frame,
};
use uk_server::{
    ServerReloadError,
    config::{CredentialConfig, LimitConfig, ServerConfig},
    run_on_listener_until_shutdown_with_reload, server_reload_channel,
};

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

const ROTATED_CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUbKiGvhPFpGKNHR7j/6IXUhFdHiswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcxMzA5MTEzMloXDTM2MDcx
MDA5MTEzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAkFhamPCkNJ11kWw3cFy+/8mokhXfr21B6uD5uCXYru+2
RxnV0ALFBzfA42ZcRuesSmlwauQKBnwYD6VfYNJWL0n+UibPI57cNW5yDQg04PY9
hMoexD9Ls9e2DSpP7Xa2ROx5kbI+1epR1Couu7vFcIVHahz7y8O/QH97xqrMBzmP
4EEEQKYi61YvUbHRYdFLOJZA2qe2T9CMJVQkwGI2vGHlUpNdP7BYFqj787Y/d+DI
2nnS/UFm7Hr1S3oBdwkcoqdPC4wqSq4akyYppKuWS9/fpyC+Oo2XCAFQ47YsPguV
2UjmoBG4hIycdi9ffAKUH9O3lzp7FYT5uIhwG4PwywIDAQABo4GSMIGPMB0GA1Ud
DgQWBBQgGGr6Btii4e151B3kGUK0enNy9DAfBgNVHSMEGDAWgBQgGGr6Btii4e15
1B3kGUK0enNy9DAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBABhyQN2prI40OBsUAMkNtwIGP1ApVuTMKHd7KyA/NB+WIW1Q
W5tBG2g375X5BX8H9+FlVV57Y5lLf0ypUI7Dp6Kwx3Opd77r1IUGT4/SltUxAa04
0epEQiIKXl/m7dV+XqKMzftn/q92ZXib3/Cy+3SdYoUoD/p4sXcvJ27Dt6pZFHru
Eyk0ziHhZXvMWYm8k5HUx4/KJrJ14v50Y3ySU7B9FnqwMztL4voIQpA7GeSfsQZY
a2QH+2MZeMVBaZQ8jAjq24WcpAM1Hx26UOmIy85/NvPFZBbT8ggH2r8CKYjiDqcL
C2n4SLoR1xpiEaImSSin581IyIJ4vFLJYsUfPJ8=
-----END CERTIFICATE-----
";

const ROTATED_KEY_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCQWFqY8KQ0nXWR
bDdwXL7/yaiSFd+vbUHq4Pm4Jdiu77ZHGdXQAsUHN8DjZlxG56xKaXBq5AoGfBgP
pV9g0lYvSf5SJs8jntw1bnINCDTg9j2Eyh7EP0uz17YNKk/tdrZE7HmRsj7V6lHU
Ki67u8VwhUdqHPvLw79Af3vGqswHOY/gQQRApiLrVi9RsdFh0Us4lkDap7ZP0Iwl
VCTAYja8YeVSk10/sFgWqPvztj934MjaedL9QWbsevVLegF3CRyip08LjCpKrhqT
Jimkq5ZL39+nIL46jZcIAVDjtiw+C5XZSOagEbiEjJx2L198ApQf07eXOnsVhPm4
iHAbg/DLAgMBAAECggEARtPz8KP0DxVMgUUWlv4LgrvTCYvOLOhxte0a2+9GOeDK
Em1s6xrQz0/eSDcMBIbdlc3TKcAn4zK1I8hD2uCbBa1LK8h7T8E90MIXGKn0OIbb
fPMo0ac1YFPystcWTTE5EuzuYj2Sc6j86hygveHPaf0cI8eBDmVIzT9A3yUj5E7v
zKesn/CDhLvbaWwbGAEAX20MLJmZ4LYzIDsBj/hTFBGYPgH56Ri3MnQjFHod4Wel
8H0+W8OkVwhFe8NS65W4reWCCFF+yyEWk1x5C7gXCAwlGr/3+r2cEXkDo9AAS1CC
MDBkU3aQcG1XR9+l/jFhhIGkeViqB/cuq5qk7ozbYQKBgQDC/18ZShjY5r+hnfrf
WU/NayJFY0ZjNE2uFMKztgVu/d4QRPOBqJSIHDIGLr7Si8Lkmz6pKHvqlluRhfds
I2zD7HLGsyDLQvrVMedOb3DOoMtgZ2PtQJNIEH3Ln9ePm+trK2TvOV3fIu8V76Jy
McKFtQscTw2e1vEmvNa2LWhCaQKBgQC9gGtC7ozhJlSbISVrew84ejh8vCFpke8S
C2yqMMQFqMr3bj/mdL7MHbhOHL9dCV48MhYnxO39Jqf1lE57q4YFy9MwloxmNKW1
VeKe1R57TubbcU7nuPVFV3qw9nZv9p0zirtAVpU/v3lCRt+blS5m3IA4Wr8WWj05
AE0NE/iLEwKBgQCmGQDYedVQbL0u3XKkbV8civVWRYnfVt4UOnreuV1Hfdd55EHH
X+GlTt8NhSPmFEaek958GI/08r5s5sAqzMII4Y+i0VJN0W/3ydpNZX+hgjW6mFb1
8NuDtwhwOmdTXGzbjMsdOrBLMWaWONkWjGw1mFEue+gONOiVJqV96I+2gQKBgG7Y
smVJYrDEmhLP9bKEHigcHfSgmy7EhUJZ2mtG8TKaRHctT0V/nqeI7ukKGcnTFANE
DP+gStGcjfyxjqL6dv/m9RbjySZzv0ZuAYyE/zqDsbhE9DHJV/cCr6rZz/e4GsYu
bU+6Fb1fRA/Hoz6/qY/ThVDxi/sIN+2ixm9S8jxvAoGAEJsnJ2UltVmxABZ7SI5l
1DAVywgdd2a0KD2tAJ/2xtWwLUDSXcEdjV6OmVFP+a1NmdJy8c8464LhVi1zuklQ
ynyYvuWbr7hzVILrpTzcxdlFzLwlD9SUIu7xUP9k3Xg8CjTZfakgwNWRUo5L/BcT
w/AVoMNYXILLNFPO133rNMo=
-----END PRIVATE KEY-----
";

const KEY_ID: &str = "e2e-client";
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const WRONG_SECRET: &str = "fedcba9876543210fedcba9876543210";
const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REPLY_NOT_ALLOWED: u8 = 0x02;
const SOCKS_REPLY_HOST_UNREACHABLE: u8 = 0x04;
const HALF_CLOSE_REQUEST: &[u8] = b"Uncrowned King half-close request";
const HALF_CLOSE_RESPONSE: &[u8] = b"Uncrowned King half-close response";
const TARGET_HALF_CLOSE_GREETING: &[u8] = b"Uncrowned King target half-close greeting";
const TARGET_HALF_CLOSE_LATE_REQUEST: &[u8] = b"Uncrowned King target half-close late request";
const TARGET_HALF_CLOSE_TIMEOUT_GREETING: &[u8] =
    b"Uncrowned King target half-close timeout greeting";
const LARGE_PAYLOAD_LEN: usize = 128 * 1024 + 123;
const SMALL_FRAME_PAYLOAD_LEN: usize = 8 * 1024 + 37;
const TEST_LOOPBACK_PORT_BASE: u16 = 20_000;
// Keep hand-picked test ports below Linux's default ephemeral range
// (32768+) so parallel bind(127.0.0.1:0) tests do not race with them.
const TEST_LOOPBACK_PORT_SPAN: u16 = 12_000;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
static NEXT_LOOPBACK_PORT_OFFSET: AtomicU16 = AtomicU16::new(0);
static TEST_LOOPBACK_START_OFFSET: OnceLock<u16> = OnceLock::new();

type TestError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_tcp_through_socks5_to_echo_target() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_tcp_relay_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_udp_through_socks5_to_echo_target() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_udp_relay_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drops_oversized_socks_udp_datagram_without_closing_session() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_oversized_socks_udp_datagram_drop_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drops_oversized_target_udp_datagram_without_closing_flow() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_oversized_target_udp_datagram_drop_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enforces_declared_udp_associate_client_endpoint() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_declared_udp_client_endpoint_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_multiple_udp_targets_over_one_socks5_association() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_multi_target_udp_relay_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovers_udp_association_after_carrier_disconnect() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_udp_carrier_recovery_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn respects_disabled_udp_stream_fallback_setting() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_udp_stream_fallback_disabled_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn treats_zero_udp_flow_capacity_as_disabled_fallback() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_udp_zero_flow_capacity_fallback_disabled_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_udp_associate_failure_when_server_is_unavailable() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_udp_associate_server_unavailable_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_udp_associate_when_udp_flow_limit_is_zero() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_zero_udp_flow_limit_associate_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enforces_udp_flow_limit_per_session() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_udp_flow_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn releases_idle_udp_flow_for_new_target() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_udp_flow_idle_reuse_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_udp_flow_alive_on_downstream_activity() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_udp_downstream_activity_idle_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_expires_idle_udp_flow_for_new_target() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_server_udp_flow_idle_reuse_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_data_sent_before_socks_success_reply() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_early_socks_data_e2e()).await?
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
async fn reports_auth_failure_during_handshake() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_auth_failure_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn falls_back_to_secondary_server_addr_during_handshake() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_handshake_fallback_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn falls_back_to_secondary_server_addr_after_primary_handshake_timeout()
-> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_handshake_timeout_fallback_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_every_failed_server_addr_during_handshake() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_all_handshake_endpoints_failed_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_expired_auth_challenge_during_handshake() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_expired_auth_challenge_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_oversized_auth_response_during_handshake() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_oversized_auth_response_error_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_unexpected_auth_response_frame() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_unexpected_auth_response_frame_error_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_zero_id_tcp_close() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_zero_id_tcp_close_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_zero_id_udp_close() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_zero_id_udp_close_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_malformed_tcp_close() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_malformed_tcp_close_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_malformed_udp_close() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_malformed_udp_close_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_malformed_tcp_open_flags() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_malformed_tcp_open_flags_error_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_invalid_target_for_malformed_udp_open() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_malformed_udp_open_target_error_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_existing_flow_after_duplicate_tcp_open() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_duplicate_tcp_open_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_existing_udp_flow_after_duplicate_udp_open() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_duplicate_udp_open_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_tcp_flow_after_wrong_protocol_udp_close() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_wrong_protocol_udp_close_on_tcp_flow_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_udp_flow_after_wrong_protocol_tcp_close() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_wrong_protocol_tcp_close_on_udp_flow_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_tcp_flow_after_wrong_protocol_udp_data() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_wrong_protocol_udp_data_on_tcp_flow_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_udp_flow_after_wrong_protocol_tcp_data() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_wrong_protocol_tcp_data_on_udp_flow_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_session_alive_after_unknown_tcp_data() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_unknown_tcp_data_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_session_alive_after_unknown_udp_data() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_unknown_udp_data_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_reserved_relay_flow_ids() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_reserved_flow_id_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_unexpected_session_frame() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_unexpected_session_frame_error_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_malformed_server_relay_frame() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_malformed_server_relay_frame_error_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_wrong_protocol_server_frame() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_wrong_protocol_server_frame_error_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_non_empty_open_ack() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_non_empty_open_ack_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_oversized_server_frame_during_open() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_oversized_server_frame_during_open_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_oversized_client_frame_to_server() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_oversized_client_frame_error_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_protocol_error_for_nonzero_id_ping() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_nonzero_id_ping_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responds_to_authenticated_ping() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_authenticated_ping_pong_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_listener_stops_on_shutdown_signal() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_server_listener_shutdown_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_exposes_health_readiness_and_metrics() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_server_observability_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_exposes_health_readiness_and_relay_metrics() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(15), run_client_observability_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_atomically_reloads_access_control() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_server_access_control_reload_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_atomically_rotates_tls_identity() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_server_tls_identity_reload_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_atomically_rotates_quic_identity() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_server_quic_identity_reload_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_atomically_reloads_connection_config() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(15),
        run_client_connection_config_reload_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_reload_supersedes_in_flight_handshake() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_client_reload_during_handshake_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_shutdown_closes_authenticated_session() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_server_active_session_shutdown_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_listener_stops_on_shutdown_signal() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_socks_listener_shutdown_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_listener_cancels_pending_open_on_shutdown_signal() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_socks_listener_shutdown_cancels_pending_open_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_listener_cancels_pending_udp_open_on_shutdown_signal() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_socks_listener_shutdown_cancels_pending_udp_open_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_listener_stops_while_server_connect_is_pending() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_socks_listener_shutdown_during_connect_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_udp_associate_stops_while_server_connect_is_pending() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_socks_udp_associate_shutdown_during_connect_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_udp_datagram_stops_while_server_reconnect_is_pending() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_socks_udp_datagram_shutdown_during_reconnect_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_domain_socks_target_to_echo_target() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_domain_relay_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn applies_credential_policy_group() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_policy_group_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maps_policy_group_mismatch_to_socks_not_allowed() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_policy_group_mismatch_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_ipv6_socks_target_to_echo_target() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_ipv6_relay_e2e()).await?
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
async fn closes_target_after_half_close_drain_timeout() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_half_close_timeout_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_client_after_half_close_drain_timeout() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_client_half_close_timeout_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maps_stream_limit_to_socks_general_failure() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_stream_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grows_carrier_pool_when_session_stream_limit_is_reached() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_pool_growth_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enforces_server_session_limit() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_server_session_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enforces_server_handshake_limit() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_server_handshake_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_concurrent_socks_flows_over_one_session() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_concurrent_multiplex_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_many_concurrent_socks_flows_over_one_session() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(20), run_many_concurrent_multiplex_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_flow_when_buffered_byte_limit_is_exceeded() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_buffered_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_flow_when_client_buffered_byte_limit_is_exceeded() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_client_buffered_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_server_session_after_client_flow_resource_limit() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_client_flow_resource_limit_keeps_session_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_large_payload_across_frames() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_large_payload_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_large_payload_with_small_frame_limit() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_small_frame_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnects_after_server_idle_timeout() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_idle_reconnect_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expires_idle_session_without_open_flows_despite_ping() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_no_flow_ping_idle_expiry_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_idle_tcp_flow_alive_with_ping() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_idle_flow_keepalive_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_session_when_keepalive_pong_is_missing() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_missing_pong_keepalive_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_session_when_keepalive_pong_payload_is_invalid() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_invalid_pong_keepalive_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_session_when_keepalive_pong_nonce_does_not_match() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_wrong_nonce_pong_keepalive_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_target_when_socks_client_disconnects() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_client_disconnect_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_open_flow_when_socks_success_reply_fails() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_socks_success_reply_failure_closes_open_flow_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_idle_socks_handshake_after_timeout() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_socks_handshake_timeout_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limits_concurrent_socks_connections() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_max_socks_connections_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancels_pending_open_when_socks_client_disconnects() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_pending_open_cancel_on_socks_disconnect_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancels_pending_udp_open_when_socks_control_disconnects() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_pending_udp_open_cancel_on_socks_control_disconnect_e2e(),
    )
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn returns_socks_failure_when_tcp_open_times_out() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_tcp_open_timeout_failure_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancels_pending_open_after_buffering_early_socks_data() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_pending_open_cancel_after_early_socks_data_e2e(),
    )
    .await?
}

async fn run_tcp_relay_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(b"Uncrowned King e2e").await?;
    let mut echoed = vec![0_u8; "Uncrowned King e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"Uncrowned King e2e");

    echo_task.await??;
    Ok(())
}

async fn run_udp_relay_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_udp_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let payload = b"Uncrowned King udp e2e";

    udp_client
        .send_to(&socks_udp_datagram(target_addr, payload), udp_relay_addr)
        .await?;

    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, target_addr);
    assert_eq!(reply_payload, payload);

    echo_task.await??;
    Ok(())
}

async fn run_oversized_socks_udp_datagram_drop_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_udp_echo_target().await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_max_frame_size(512),
    )
    .await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let oversized = vec![0x42; 900];
    let small = b"Uncrowned King udp survives oversized upstream";

    udp_client
        .send_to(&socks_udp_datagram(target_addr, &oversized), udp_relay_addr)
        .await?;
    assert_no_socks_udp_datagram(&udp_client).await?;

    udp_client
        .send_to(&socks_udp_datagram(target_addr, small), udp_relay_addr)
        .await?;
    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, target_addr);
    assert_eq!(reply_payload, small);

    echo_task.await??;
    Ok(())
}

async fn run_oversized_target_udp_datagram_drop_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_udp_oversized_then_echo_target(900).await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_max_frame_size(512),
    )
    .await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let first = b"Uncrowned King trigger oversized downstream";
    let second = b"Uncrowned King udp survives oversized downstream";

    udp_client
        .send_to(&socks_udp_datagram(target_addr, first), udp_relay_addr)
        .await?;
    assert_no_socks_udp_datagram(&udp_client).await?;

    udp_client
        .send_to(&socks_udp_datagram(target_addr, second), udp_relay_addr)
        .await?;
    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, target_addr);
    assert_eq!(reply_payload, second);

    target_task.await??;
    Ok(())
}

async fn run_declared_udp_client_endpoint_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_udp_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let declared_endpoint = udp_client.local_addr()?;
    let (_socks_control, udp_relay_addr) =
        open_socks_udp_associate_from(harness.socks_addr, declared_endpoint).await?;
    let unexpected_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let payload = b"Uncrowned King declared udp endpoint";

    unexpected_client
        .send_to(
            &socks_udp_datagram(target_addr, b"unexpected udp source"),
            udp_relay_addr,
        )
        .await?;
    udp_client
        .send_to(&socks_udp_datagram(target_addr, payload), udp_relay_addr)
        .await?;

    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, target_addr);
    assert_eq!(reply_payload, payload);

    echo_task.await??;
    Ok(())
}

async fn run_multi_target_udp_relay_e2e() -> Result<(), TestError> {
    init_tracing();

    let (first_target_addr, first_echo_task) = spawn_udp_echo_target().await?;
    let (second_target_addr, second_echo_task) = spawn_udp_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_loopback_any_port_policy())).await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let first_payload = b"Uncrowned King udp first target";
    let second_payload = b"Uncrowned King udp second target";

    udp_client
        .send_to(
            &socks_udp_datagram(first_target_addr, first_payload),
            udp_relay_addr,
        )
        .await?;
    udp_client
        .send_to(
            &socks_udp_datagram(second_target_addr, second_payload),
            udp_relay_addr,
        )
        .await?;

    let mut responses = Vec::new();
    for _ in 0..2 {
        responses.push(recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?);
    }
    responses.sort_by_key(|(target, _)| target.port());

    let mut expected = vec![
        (first_target_addr, first_payload.to_vec()),
        (second_target_addr, second_payload.to_vec()),
    ];
    expected.sort_by_key(|(target, _)| target.port());
    assert_eq!(responses, expected);

    first_echo_task.await??;
    second_echo_task.await??;
    Ok(())
}

async fn run_udp_stream_fallback_disabled_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = UdpStreamFallbackDisabledServerHarness::start().await?;
    let (mut socks_control, head) = open_socks_udp_associate_reply(harness.socks_addr).await?;
    assert_eq!(head[1], SOCKS_REPLY_GENERAL_FAILURE);
    let bound_addr = read_socks_reply_addr(&mut socks_control, head[3]).await?;
    assert_eq!(bound_addr, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));

    harness.observed_no_udp_open().await?;
    Ok(())
}

async fn run_udp_zero_flow_capacity_fallback_disabled_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = UdpStreamFallbackDisabledServerHarness::start_zero_flow_capacity().await?;
    let (mut socks_control, head) = open_socks_udp_associate_reply(harness.socks_addr).await?;
    assert_eq!(head[1], SOCKS_REPLY_GENERAL_FAILURE);
    let bound_addr = read_socks_reply_addr(&mut socks_control, head[3]).await?;
    assert_eq!(bound_addr, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));

    harness.observed_no_udp_open().await?;
    Ok(())
}

async fn run_udp_associate_server_unavailable_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    fs::write(&cert_path, CERT_PEM)?;
    let server_addr = unused_loopback_addr().await?;
    let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
        server_addr: server_addr.to_string(),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: path_string(&cert_path),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds: Some(1),
        server_connect_retry_delay_millis: None,
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: None,
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
    })
    .await?;

    let (mut socks_control, head) = open_socks_udp_associate_reply(socks_addr).await?;
    assert_eq!(head[1], SOCKS_REPLY_GENERAL_FAILURE);
    let bound_addr = read_socks_reply_addr(&mut socks_control, head[3]).await?;
    assert_eq!(bound_addr, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));

    client_task.abort();
    fs::remove_dir_all(&temp_dir)?;
    Ok(())
}

async fn run_zero_udp_flow_limit_associate_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = RelayHarness::start_with_limits(None, test_limits_with_max_udp_flows(0)).await?;
    let (mut socks_control, head) = open_socks_udp_associate_reply(harness.socks_addr).await?;
    assert_eq!(head[1], SOCKS_REPLY_GENERAL_FAILURE);
    let bound_addr = read_socks_reply_addr(&mut socks_control, head[3]).await?;
    assert_eq!(bound_addr, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    Ok(())
}

async fn run_udp_flow_limit_e2e() -> Result<(), TestError> {
    init_tracing();

    let (first_target_addr, first_echo_task) = spawn_udp_echo_target().await?;
    let (second_target_addr, second_echo_task) = spawn_udp_echo_target().await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_any_port_policy()),
        test_limits_with_max_udp_flows(1),
    )
    .await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let first_payload = b"Uncrowned King udp allowed target";
    let second_payload = b"Uncrowned King udp limited target";

    udp_client
        .send_to(
            &socks_udp_datagram(first_target_addr, first_payload),
            udp_relay_addr,
        )
        .await?;
    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, first_target_addr);
    assert_eq!(reply_payload, first_payload);

    udp_client
        .send_to(
            &socks_udp_datagram(second_target_addr, second_payload),
            udp_relay_addr,
        )
        .await?;
    let mut buf = [0_u8; 1024];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), udp_client.recv_from(&mut buf))
            .await
            .is_err(),
        "second UDP target should be blocked by max_udp_flows"
    );

    first_echo_task.await??;
    second_echo_task.abort();
    Ok(())
}

async fn run_udp_flow_idle_reuse_e2e() -> Result<(), TestError> {
    init_tracing();

    let (first_target_addr, first_echo_task) = spawn_udp_echo_target().await?;
    let (second_target_addr, second_echo_task) = spawn_udp_echo_target().await?;
    let harness = RelayHarness::start_with_client_udp_idle_timeout(
        Some(allow_loopback_any_port_policy()),
        test_limits_with_max_udp_flows(1),
        1,
    )
    .await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let first_payload = b"Uncrowned King udp idle first target";
    let second_payload = b"Uncrowned King udp idle second target";

    udp_client
        .send_to(
            &socks_udp_datagram(first_target_addr, first_payload),
            udp_relay_addr,
        )
        .await?;
    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, first_target_addr);
    assert_eq!(reply_payload, first_payload);
    first_echo_task.await??;

    tokio::time::sleep(Duration::from_millis(2300)).await;

    udp_client
        .send_to(
            &socks_udp_datagram(second_target_addr, second_payload),
            udp_relay_addr,
        )
        .await?;
    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, second_target_addr);
    assert_eq!(reply_payload, second_payload);

    second_echo_task.await??;
    Ok(())
}

async fn run_udp_downstream_activity_idle_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_udp_downstream_activity_target().await?;
    let harness = RelayHarness::start_with_client_udp_idle_timeout(
        Some(allow_loopback_any_port_policy()),
        test_limits(),
        1,
    )
    .await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;

    udp_client
        .send_to(
            &socks_udp_datagram(target_addr, b"Uncrowned King downstream activity"),
            udp_relay_addr,
        )
        .await?;

    for expected in [
        b"downstream-0".as_slice(),
        b"downstream-1".as_slice(),
        b"downstream-2".as_slice(),
        b"downstream-3".as_slice(),
    ] {
        let (reply_target, reply_payload) =
            recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
        assert_eq!(reply_target, target_addr);
        assert_eq!(reply_payload, expected);
    }

    target_task.await??;
    Ok(())
}

async fn run_server_udp_flow_idle_reuse_e2e() -> Result<(), TestError> {
    init_tracing();

    let (first_target_addr, first_echo_task) = spawn_udp_echo_target().await?;
    let (second_target_addr, second_echo_task) = spawn_udp_echo_target().await?;
    let harness = RelayHarness::start_with_client_udp_idle_timeout(
        Some(allow_loopback_any_port_policy()),
        test_limits_with_udp_idle_timeout(1),
        0,
    )
    .await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let first_payload = b"Uncrowned King server udp idle first";
    let second_payload = b"Uncrowned King server udp idle second";

    udp_client
        .send_to(
            &socks_udp_datagram(first_target_addr, first_payload),
            udp_relay_addr,
        )
        .await?;
    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, first_target_addr);
    assert_eq!(reply_payload, first_payload);
    first_echo_task.await??;

    tokio::time::sleep(Duration::from_millis(2300)).await;

    udp_client
        .send_to(
            &socks_udp_datagram(second_target_addr, second_payload),
            udp_relay_addr,
        )
        .await?;
    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, second_target_addr);
    assert_eq!(reply_payload, second_payload);

    second_echo_task.await??;
    Ok(())
}

async fn run_early_socks_data_e2e() -> Result<(), TestError> {
    init_tracing();

    let early_payload = b"Uncrowned King early socks data";
    let (target_addr, echo_task) = spawn_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;

    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let mut request = socks_connect_request(target_addr);
    request.extend_from_slice(early_payload);
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    let mut connect_reply = [0_u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    let mut echoed = vec![0_u8; early_payload.len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, early_payload);

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

async fn run_client_disconnect_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_read_to_eof_target().await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;

    let (socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);
    drop(socks);

    let target_received = target_task.await??;
    assert!(target_received.is_empty());
    Ok(())
}

async fn run_socks_success_reply_failure_closes_open_flow_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = AckGatedOpenServerHarness::start().await?;
    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);

    harness.observed_tcp_open().await?;
    reset_tcp_stream(socks)?;
    harness.release_open_ack()?;

    assert_eq!(harness.received_close_code().await?, TCP_CLOSE_ERROR);
    Ok(())
}

async fn run_socks_handshake_timeout_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = RelayHarness::start_with_client_socks_timeout(None, 1).await?;
    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let mut byte = [0_u8; 1];

    assert_eq!(socks.read(&mut byte).await?, 0);
    Ok(())
}

async fn run_max_socks_connections_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = RelayHarness::start_with_max_socks_connections(None, 1).await?;
    let _first = open_idle_socks_greeting(harness.socks_addr).await?;

    let mut second = TcpStream::connect(harness.socks_addr).await?;
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(3), second.read(&mut byte)).await? {
        Ok(0) => {}
        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {}
        Ok(read) => return Err(format!("limited socks connection read {read} bytes").into()),
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

async fn open_idle_socks_greeting(socks_addr: SocketAddr) -> Result<TcpStream, TestError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

    loop {
        match try_open_idle_socks_greeting(socks_addr).await {
            Ok(socks) => return Ok(socks),
            Err(_err) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn try_open_idle_socks_greeting(socks_addr: SocketAddr) -> Result<TcpStream, TestError> {
    let mut socks = TcpStream::connect(socks_addr).await?;
    socks.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_response = [0_u8; 2];
    match tokio::time::timeout(
        Duration::from_millis(250),
        socks.read_exact(&mut method_response),
    )
    .await
    {
        Ok(Ok(_)) if method_response == [0x05, 0x00] => Ok(socks),
        Ok(Ok(_)) => Err(format!("unexpected socks method response: {method_response:?}").into()),
        Ok(Err(err))
            if matches!(
                err.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            Err(err.into())
        }
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Err("timed out waiting for socks method response".into()),
    }
}

async fn run_pending_open_cancel_on_socks_disconnect_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = PendingOpenCancelServerHarness::start().await?;
    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    drop(socks);

    assert_eq!(harness.received_close_code().await?, TCP_CLOSE_ERROR);
    Ok(())
}

async fn run_pending_udp_open_cancel_on_socks_control_disconnect_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = PendingUdpOpenCancelServerHarness::start().await?;
    let (socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));

    udp_client
        .send_to(
            &socks_udp_datagram(target_addr, b"cancel pending udp open"),
            udp_relay_addr,
        )
        .await?;
    harness.observed_udp_open().await?;
    drop(socks_control);

    assert_eq!(harness.received_close_code().await?, UDP_CLOSE_ERROR);
    Ok(())
}

async fn run_tcp_open_timeout_failure_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = PendingOpenCancelServerHarness::start_with_tcp_open_timeout(1).await?;
    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);

    let mut connect_reply = [0_u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_GENERAL_FAILURE);
    assert_eq!(harness.received_close_code().await?, TCP_CLOSE_ERROR);
    Ok(())
}

async fn run_pending_open_cancel_after_early_socks_data_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = PendingOpenCancelServerHarness::start().await?;
    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let mut request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    request.extend_from_slice(b"Uncrowned King early data before open ack");
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    drop(socks);

    assert_eq!(harness.received_close_code().await?, TCP_CLOSE_ERROR);
    Ok(())
}

async fn run_idle_reconnect_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_any_port_policy()),
        test_limits_with_idle_timeout(1),
    )
    .await?;

    let (first_target_addr, first_echo_task) = spawn_echo_target().await?;
    assert_echo_roundtrip(harness.socks_addr, first_target_addr, b"first session").await?;
    first_echo_task.await??;

    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let (second_target_addr, second_echo_task) = spawn_echo_target().await?;
    assert_echo_roundtrip(harness.socks_addr, second_target_addr, b"second session").await?;
    second_echo_task.await??;
    Ok(())
}

async fn run_no_flow_ping_idle_expiry_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits_with_idle_timeout(1)).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_ping_expect_pong(&mut carrier, Bytes::from_static(b"no-flow-ping-1")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    write_ping_expect_pong(&mut carrier, Bytes::from_static(b"no-flow-ping-2")).await?;
    tokio::time::sleep(Duration::from_millis(650)).await;

    match tokio::time::timeout(
        Duration::from_millis(200),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await
    {
        Ok(Err(FrameIoError::Closed)) => Ok(()),
        Ok(Err(err)) => Err(err.into()),
        Ok(Ok(frame)) => Err(format!("unexpected frame after idle expiry: {frame:?}").into()),
        Err(_) => Err("no-flow ping extended the idle session".into()),
    }
}

async fn run_idle_flow_keepalive_e2e() -> Result<(), TestError> {
    init_tracing();

    let first_payload = b"before-idle";
    let second_payload = b"after-idle";
    let (target_addr, target_task) =
        spawn_two_stage_echo_target(first_payload.len(), second_payload.len()).await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_idle_timeout(1),
    )
    .await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(first_payload).await?;
    let mut first_echo = vec![0_u8; first_payload.len()];
    socks.read_exact(&mut first_echo).await?;
    assert_eq!(first_echo, first_payload);

    tokio::time::sleep(Duration::from_millis(1_500)).await;

    socks.write_all(second_payload).await?;
    let mut second_echo = vec![0_u8; second_payload.len()];
    socks.read_exact(&mut second_echo).await?;
    assert_eq!(second_echo, second_payload);
    target_task.await??;
    Ok(())
}

async fn run_missing_pong_keepalive_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = MissingPongServerHarness::start().await?;
    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    let mut connect_reply = [0_u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    harness.observed_client_close_after_ping().await?;
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), socks.read(&mut byte)).await??,
        0
    );
    Ok(())
}

async fn run_invalid_pong_keepalive_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = MissingPongServerHarness::start_with_empty_pong().await?;
    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    let mut connect_reply = [0_u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    harness.observed_client_close_after_ping().await?;
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), socks.read(&mut byte)).await??,
        0
    );
    Ok(())
}

async fn run_wrong_nonce_pong_keepalive_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = MissingPongServerHarness::start_with_wrong_nonce_pong().await?;
    let mut socks = TcpStream::connect(harness.socks_addr).await?;
    let request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    let mut connect_reply = [0_u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    harness.observed_client_close_after_ping().await?;
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), socks.read(&mut byte)).await??,
        0
    );
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

/// Volume relayed by the throughput benchmarks. Large enough to be
/// representative on loopback, small enough to stay well within the test
/// timeout on CI.
const THROUGHPUT_BYTES: usize = 32 * 1024 * 1024;
const THROUGHPUT_CHUNK: usize = 64 * 1024;

// Manual throughput benchmark — NOT a CI gate. A single high-throughput flow
// is shed if the consuming task falls behind its bounded per-flow queue
// (FLOW_FRAME_QUEUE_CAPACITY = 32 frames × RELAY_BUFFER_SIZE), because the
// shared carrier reader drops an overflowing flow rather than
// head-of-line-blocking every other flow. Under a loaded CI runner the
// consumer is CPU-starved and the flow is shed on *both* carriers, so a
// "received == total" assertion is not deterministic here. It is therefore
// `#[ignore]`d and run on demand:
//
//     cargo test -p uk-client --test tcp_relay_e2e --release -- --ignored --nocapture measures_quic_carrier_throughput
//
// See docs/performance.md for the finding, numbers, and mitigations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load-sensitive throughput benchmark; run manually with --ignored"]
async fn measures_quic_carrier_throughput() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(30), run_quic_throughput_e2e()).await?
}

async fn run_quic_throughput_e2e() -> Result<(), TestError> {
    // QUIC transport flow control paces the source, so on an unloaded machine a
    // single flow sustains the full volume; under enough consumer CPU
    // starvation the app-level per-flow queue can still overflow and shed
    // (hence this is a manual, `#[ignore]`d benchmark).
    run_throughput_e2e(true, THROUGHPUT_BYTES).await
}

const ISOLATION_SAMPLES: usize = 400;
const ISOLATION_PING_BYTES: usize = 256;
const ISOLATION_BULK_CHUNK: usize = 64 * 1024;

// Manual benchmark — NOT a CI gate. Quantifies the connection pool's bulk/latency
// isolation (whitepaper §13): it measures the round-trip latency of a small
// interactive flow while a bulk upload flow saturates, comparing two carrier
// layouts that both admit exactly two flows:
//
//   * co-located: max_carrier_sessions = 1, max_streams = 2  (one shared carrier)
//   * pooled:     max_carrier_sessions = 2, max_streams = 1  (a carrier each)
//
// On one shared carrier the interactive flow contends for the per-session writer
// mutex (and the single carrier reader) with the bulk flow; the pool puts it on
// its own carrier. Timing-sensitive, so `#[ignore]`d and run on demand:
//
//     cargo test -p uk-client --test tcp_relay_e2e --release -- --ignored --nocapture measures_connection_pool_latency_isolation
//
// See docs/performance.md for observed numbers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load-sensitive latency benchmark; run manually with --ignored"]
async fn measures_connection_pool_latency_isolation() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(60), run_pool_isolation_benchmark()).await?
}

async fn run_pool_isolation_benchmark() -> Result<(), TestError> {
    let colocated = run_pool_isolation_e2e(1, 2).await?;
    let pooled = run_pool_isolation_e2e(2, 1).await?;

    eprintln!(
        "pool-isolation interactive latency under a saturating bulk flow \
         ({ISOLATION_SAMPLES} round-trips):"
    );
    eprintln!(
        "  co-located (1 carrier, max_streams=2): p50={:.2}ms p99={:.2}ms",
        millis(colocated.0),
        millis(colocated.1)
    );
    eprintln!(
        "  pooled     (2 carriers, max_streams=1): p50={:.2}ms p99={:.2}ms",
        millis(pooled.0),
        millis(pooled.1)
    );
    let p99_ratio = colocated.1.as_secs_f64() / pooled.1.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!("  p99 improvement (co-located / pooled): {p99_ratio:.1}x");
    Ok(())
}

/// Runs the isolation scenario for one carrier layout and returns the interactive
/// flow's (p50, p99) round-trip latency while a bulk upload flow saturates.
async fn run_pool_isolation_e2e(
    max_carrier_sessions: u64,
    max_streams: u64,
) -> Result<(Duration, Duration), TestError> {
    init_tracing();

    let (echo_addr, echo_task) = spawn_multi_echo_target().await?;
    let (sink_addr, sink_task) = spawn_sink_target().await?;

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut limits = throughput_limits();
    limits.max_streams = Some(max_streams);
    let config = test_server_config(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &cert_path,
        &key_path,
        limits,
        Some(&policy_path),
        30,
    );
    let (server_addr, server_task) = start_uk_server_until_shutdown(config, async {
        let _ = shutdown_rx.await;
    })
    .await?;

    let mut client_config = test_client_config(server_addr, &cert_path, SECRET);
    client_config.max_buffered_bytes_per_session = Some(THROUGHPUT_BUFFER_BYTES);
    client_config.max_buffered_bytes_per_flow = Some(THROUGHPUT_BUFFER_BYTES);
    client_config.max_carrier_sessions = Some(max_carrier_sessions);
    let (socks_addr, client_task) = start_socks5_listener(client_config).await?;

    // Open the bulk flow first so it occupies the first carrier, then saturate it.
    let (bulk_socks, bulk_reply) = open_socks_connect(socks_addr, sink_addr).await?;
    assert_eq!(bulk_reply[1], SOCKS_REPLY_SUCCEEDED);
    let bulk_stop = Arc::new(AtomicBool::new(false));
    let bulk_task = spawn_bulk_upload(bulk_socks, Arc::clone(&bulk_stop));
    // Let the bulk flow ramp up before sampling.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (mut ping_socks, ping_reply) = open_socks_connect(socks_addr, echo_addr).await?;
    assert_eq!(ping_reply[1], SOCKS_REPLY_SUCCEEDED);
    ping_socks.set_nodelay(true)?;
    let request = patterned_payload(ISOLATION_PING_BYTES);
    let mut echoed = vec![0_u8; ISOLATION_PING_BYTES];
    let mut samples = Vec::with_capacity(ISOLATION_SAMPLES);
    for _ in 0..ISOLATION_SAMPLES {
        let start = std::time::Instant::now();
        ping_socks.write_all(&request).await?;
        ping_socks.read_exact(&mut echoed).await?;
        samples.push(start.elapsed());
        assert_eq!(echoed, request, "interactive echo payload mismatch");
    }

    bulk_stop.store(true, Ordering::SeqCst);
    drop(ping_socks);
    let _ = bulk_task.await;

    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(5), server_task).await???;
    client_task.abort();
    echo_task.abort();
    sink_task.abort();
    let _ = fs::remove_dir_all(temp_dir);

    samples.sort_unstable();
    Ok((percentile(&samples, 50.0), percentile(&samples, 99.0)))
}

/// A target that accepts one connection and drains everything sent to it,
/// letting a bulk upload flow run without backpressure from the target.
async fn spawn_sink_target()
-> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let mut buf = vec![0_u8; ISOLATION_BULK_CHUNK];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        Ok(())
    });
    Ok((addr, task))
}

/// Continuously uploads through `socks` until `stop` is set, saturating the
/// carrier the bulk flow lives on.
fn spawn_bulk_upload(mut socks: TcpStream, stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = socks.set_nodelay(true);
        let chunk = vec![0x5a_u8; ISOLATION_BULK_CHUNK];
        while !stop.load(Ordering::SeqCst) {
            if socks.write_all(&chunk).await.is_err() {
                break;
            }
        }
    })
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let index = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

#[allow(clippy::cast_precision_loss)]
fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

/// Server + client limits with generous relay buffers, so a bulk benchmark
/// measures steady-state throughput rather than the per-flow shed-load cap.
const THROUGHPUT_BUFFER_BYTES: u64 = 16 * 1024 * 1024;

fn throughput_limits() -> LimitConfig {
    LimitConfig {
        max_buffered_bytes_per_session: Some(THROUGHPUT_BUFFER_BYTES),
        max_buffered_bytes_per_flow: Some(THROUGHPUT_BUFFER_BYTES),
        ..test_limits()
    }
}

async fn run_throughput_e2e(use_quic: bool, volume: usize) -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_source_target(volume).await?;

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_policy(target_addr.port()))?;

    let quic_addr = if use_quic {
        Some(unused_udp_loopback_addr().await?)
    } else {
        None
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut config = test_server_config(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &cert_path,
        &key_path,
        throughput_limits(),
        Some(&policy_path),
        30,
    );
    if let Some(quic_addr) = quic_addr {
        config.quic_listen = Some(quic_addr.to_string());
    }
    let (server_addr, server_task) = start_uk_server_until_shutdown(config, async {
        let _ = shutdown_rx.await;
    })
    .await?;

    let mut client_config = test_client_config(server_addr, &cert_path, SECRET);
    if let Some(quic_addr) = quic_addr {
        client_config.server_addr = format!("quic://{quic_addr}");
    }
    client_config.max_buffered_bytes_per_session = Some(THROUGHPUT_BUFFER_BYTES);
    client_config.max_buffered_bytes_per_flow = Some(THROUGHPUT_BUFFER_BYTES);
    let (socks_addr, client_task) = start_socks5_listener(client_config).await?;

    let (socks, connect_reply) = open_socks_connect(socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);
    let carrier = if use_quic { "quic" } else { "tls" };
    let mib_per_s = measure_download_throughput(socks, volume).await?;
    eprintln!("throughput[{carrier}]: {mib_per_s:.1} MiB/s over {volume} bytes");

    target_task.await??;
    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(5), server_task).await???;
    client_task.abort();
    let _ = fs::remove_dir_all(temp_dir);
    Ok(())
}

/// Measures unidirectional download throughput (target → client) in MiB/s.
///
/// The client only reads, so the relay's per-flow select loop is not contended
/// by a simultaneous upload — this measures the sustained relay rate for the
/// common download-heavy proxy workload. The client closes only after reading
/// every byte, so there is no dependency on close ordering.
#[allow(clippy::cast_precision_loss)] // total is a few MiB, well within f64.
async fn measure_download_throughput(socks: TcpStream, total: usize) -> Result<f64, TestError> {
    socks.set_nodelay(true)?;
    let (mut read_half, _write_half) = socks.into_split();
    let start = std::time::Instant::now();

    let mut received = 0;
    let mut buf = vec![0_u8; THROUGHPUT_CHUNK];
    while received < total {
        let read = read_half.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        received += read;
    }
    let elapsed = start.elapsed();

    if received != total {
        return Err(format!("throughput mismatch: received {received} of {total} bytes").into());
    }
    // `_write_half` and `read_half` drop here, closing the connection and
    // letting the source target's trailing read observe EOF.
    let mib = total as f64 / (1024.0 * 1024.0);
    Ok(mib / elapsed.as_secs_f64())
}

/// A target that streams `total` bytes to the connecting relay, then holds the
/// connection open until the client closes (so the download completes before
/// any close is propagated).
async fn spawn_source_target(
    total: usize,
) -> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let chunk = vec![0x5a_u8; THROUGHPUT_CHUNK];
        let mut sent = 0;
        while sent < total {
            let len = THROUGHPUT_CHUNK.min(total - sent);
            stream.write_all(&chunk[..len]).await?;
            sent += len;
        }
        // Hold open until the client closes, so the full download is delivered.
        let mut drain = [0_u8; 1];
        let _ = stream.read(&mut drain).await?;
        Ok(())
    });
    Ok((addr, task))
}

// Soak / chaos: keep a set of long-lived flows continuously relaying through one
// client session while periodically injecting denied-target flows, then confirm
// the session stays healthy with every byte intact. Uses persistent flows
// (steady request/response) rather than connect churn, so it does not exhaust
// ephemeral ports over a long run. Not a CI gate (duration-based); run manually
// and set the duration via UK_SOAK_SECONDS (default 2s):
//
//     UK_SOAK_SECONDS=86400 cargo test -p uk-client --test tcp_relay_e2e --release \
//         -- --ignored --nocapture soak_sustained_relay_and_chaos
//
// For memory / file-descriptor monitoring, run it under `/usr/bin/time -l`
// (macOS) or `/usr/bin/time -v` (Linux) and watch max RSS across a long run.
const SOAK_CONCURRENCY: usize = 16;

fn soak_limits() -> LimitConfig {
    // Enough concurrent streams for the persistent flows plus injected chaos.
    LimitConfig {
        max_streams: Some(64),
        ..test_limits()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "duration-based soak/chaos; run manually with --ignored (UK_SOAK_SECONDS)"]
async fn soak_sustained_relay_and_chaos() -> Result<(), TestError> {
    init_tracing();

    let seconds: u64 = std::env::var("UK_SOAK_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2);

    let (target_addr, target_task) = spawn_multi_echo_target().await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        soak_limits(),
    )
    .await?;
    let denied_addr = unused_loopback_addr().await?;
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);

    // Persistent flows, each ping-ponging a payload for the whole duration.
    let mut flows = Vec::with_capacity(SOAK_CONCURRENCY);
    for index in 0..SOAK_CONCURRENCY {
        let socks_addr = harness.socks_addr;
        flows.push(tokio::spawn(async move {
            let (mut socks, connect_reply) = open_socks_connect(socks_addr, target_addr).await?;
            assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);
            let payload = format!("uncrowned king soak flow {index}").into_bytes();
            let mut echoed = vec![0_u8; payload.len()];
            let mut round_trips = 0_u64;
            while std::time::Instant::now() < deadline {
                socks.write_all(&payload).await?;
                socks.read_exact(&mut echoed).await?;
                if echoed != payload {
                    return Err("soak payload corrupted".into());
                }
                round_trips += 1;
            }
            Ok::<u64, TestError>(round_trips)
        }));
    }

    // Chaos: inject denied flows at a bounded rate; each must fail without
    // tearing down the shared session that the persistent flows depend on.
    let mut denied = 0_u64;
    while std::time::Instant::now() < deadline {
        expect_denied_flow(harness.socks_addr, denied_addr).await?;
        denied += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut total_round_trips = 0_u64;
    for flow in flows {
        total_round_trips += flow.await??;
    }
    assert!(total_round_trips > 0, "no round trips completed");

    // The long-lived session survived the chaos; a fresh flow still works.
    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);
    let probe = b"soak final health probe";
    socks.write_all(probe).await?;
    let mut echoed = vec![0_u8; probe.len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, probe);

    eprintln!(
        "soak: {total_round_trips} round trips across {SOAK_CONCURRENCY} flows + {denied} \
         denied-flow chaos over {seconds}s; session healthy"
    );
    target_task.abort();
    Ok(())
}

/// A denied SOCKS CONNECT must fail (policy denial or dropped connection) rather
/// than succeed, and must not tear down the shared client session.
async fn expect_denied_flow(
    socks_addr: SocketAddr,
    denied_addr: SocketAddr,
) -> Result<(), TestError> {
    match open_socks_connect(socks_addr, denied_addr).await {
        Ok((_socks, connect_reply)) if connect_reply[1] == SOCKS_REPLY_SUCCEEDED => {
            Err("denied target unexpectedly succeeded".into())
        }
        // A non-success reply or a dropped connection are both acceptable.
        _ => Ok(()),
    }
}

async fn spawn_multi_echo_target()
-> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let mut buf = vec![0_u8; 16 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buf[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok((addr, task))
}

async fn run_small_frame_limit_e2e() -> Result<(), TestError> {
    init_tracing();

    let payload = patterned_payload(SMALL_FRAME_PAYLOAD_LEN);
    let (target_addr, target_task) = spawn_fixed_size_echo_target(payload.len()).await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_max_frame_size(1024),
    )
    .await?;

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
    // Pin the pool to a single carrier so the per-session stream limit is the
    // binding constraint; otherwise the pool would open a second carrier for the
    // second flow. Pool growth under the stream limit is covered separately by
    // `grows_carrier_pool_when_session_stream_limit_is_reached`.
    let harness = RelayHarness::start_with_limits_and_pool(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_max_streams(1),
        1,
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

async fn run_pool_growth_e2e() -> Result<(), TestError> {
    init_tracing();

    // Each server session admits only one flow. Two concurrently-open flows can
    // therefore only both succeed if the client pool grows to a second carrier.
    let first_payload = patterned_payload(4097);
    let mut second_payload = patterned_payload(7003);
    second_payload.reverse();
    let barrier = Arc::new(Barrier::new(2));
    let (first_target_addr, first_target_task) =
        spawn_barrier_echo_target(first_payload.len(), Arc::clone(&barrier)).await?;
    let (second_target_addr, second_target_task) =
        spawn_barrier_echo_target(second_payload.len(), Arc::clone(&barrier)).await?;
    let harness = RelayHarness::start_with_limits_and_pool(
        Some(allow_loopback_any_port_policy()),
        test_limits_with_max_streams(1),
        2,
    )
    .await?;

    let first_open = open_socks_connect(harness.socks_addr, first_target_addr);
    let second_open = open_socks_connect(harness.socks_addr, second_target_addr);
    let ((mut first_socks, first_reply), (mut second_socks, second_reply)) =
        tokio::try_join!(first_open, second_open)?;
    assert_eq!(
        first_reply[1], SOCKS_REPLY_SUCCEEDED,
        "first flow should open on the first carrier"
    );
    assert_eq!(
        second_reply[1], SOCKS_REPLY_SUCCEEDED,
        "second flow should open on a second pooled carrier despite max_streams=1"
    );

    tokio::try_join!(
        first_socks.write_all(&first_payload),
        second_socks.write_all(&second_payload)
    )?;
    let mut first_echo = vec![0_u8; first_payload.len()];
    let mut second_echo = vec![0_u8; second_payload.len()];
    tokio::try_join!(
        first_socks.read_exact(&mut first_echo),
        second_socks.read_exact(&mut second_echo)
    )?;
    assert_eq!(first_echo, first_payload);
    assert_eq!(second_echo, second_payload);

    first_socks.shutdown().await?;
    second_socks.shutdown().await?;
    assert_eq!(first_target_task.await??, first_payload);
    assert_eq!(second_target_task.await??, second_payload);
    Ok(())
}

async fn run_server_session_limit_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits_with_max_sessions(1)).await?;
    let _held_carrier = connect_authenticated_carrier(harness.client_config(SECRET)).await?;
    let error = run_handshake(harness.client_config(SECRET))
        .await
        .expect_err("second authenticated carrier should fail while max_sessions is exhausted");
    let text = error.to_string();

    assert!(
        text.contains("ResourceLimit"),
        "session limit error should report ResourceLimit, got: {text}"
    );
    Ok(())
}

async fn run_server_handshake_limit_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits_with_max_handshakes(1)).await?;
    let _held_handshake = connect_tls_carrier_after_probe(&harness).await?;

    let mut rejected = TcpStream::connect(harness.server_addr).await?;
    let mut buf = [0_u8; 1];
    let bytes_read =
        tokio::time::timeout(Duration::from_secs(3), rejected.read(&mut buf)).await??;
    assert_eq!(
        bytes_read, 0,
        "server should close over-limit handshake TCP connections cleanly"
    );
    Ok(())
}

async fn run_concurrent_multiplex_e2e() -> Result<(), TestError> {
    init_tracing();

    let first_payload = patterned_payload(4097);
    let mut second_payload = patterned_payload(7003);
    second_payload.reverse();
    let barrier = Arc::new(Barrier::new(2));
    let (first_target_addr, first_target_task) =
        spawn_barrier_echo_target(first_payload.len(), Arc::clone(&barrier)).await?;
    let (second_target_addr, second_target_task) =
        spawn_barrier_echo_target(second_payload.len(), Arc::clone(&barrier)).await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_any_port_policy()),
        test_limits_with_max_streams(2),
    )
    .await?;

    let first_open = open_socks_connect(harness.socks_addr, first_target_addr);
    let second_open = open_socks_connect(harness.socks_addr, second_target_addr);
    let ((mut first_socks, first_reply), (mut second_socks, second_reply)) =
        tokio::try_join!(first_open, second_open)?;
    assert_eq!(first_reply[1], SOCKS_REPLY_SUCCEEDED);
    assert_eq!(second_reply[1], SOCKS_REPLY_SUCCEEDED);

    tokio::try_join!(
        first_socks.write_all(&first_payload),
        second_socks.write_all(&second_payload)
    )?;

    let mut first_echo = vec![0_u8; first_payload.len()];
    let mut second_echo = vec![0_u8; second_payload.len()];
    tokio::try_join!(
        first_socks.read_exact(&mut first_echo),
        second_socks.read_exact(&mut second_echo)
    )?;
    assert_eq!(first_echo, first_payload);
    assert_eq!(second_echo, second_payload);

    first_socks.shutdown().await?;
    second_socks.shutdown().await?;
    assert_eq!(first_target_task.await??, first_payload);
    assert_eq!(second_target_task.await??, second_payload);
    Ok(())
}

async fn run_many_concurrent_multiplex_e2e() -> Result<(), TestError> {
    const FLOW_COUNT: usize = 32;

    init_tracing();

    let barrier = Arc::new(Barrier::new(FLOW_COUNT));
    let mut targets = Vec::with_capacity(FLOW_COUNT);
    for index in 0..FLOW_COUNT {
        let mut payload = patterned_payload(1024 + index * 37);
        payload[0] = u8::try_from(index)?;
        let (addr, task) = spawn_barrier_echo_target(payload.len(), Arc::clone(&barrier)).await?;
        targets.push((addr, task, payload));
    }

    let mut limits = test_limits_with_max_streams(FLOW_COUNT as u64);
    limits.max_outbound_dials_per_session = Some(FLOW_COUNT as u64);
    let harness =
        RelayHarness::start_with_limits(Some(allow_loopback_any_port_policy()), limits).await?;

    let mut client_tasks = JoinSet::new();
    for (target_addr, _, payload) in &targets {
        let socks_addr = harness.socks_addr;
        let target_addr = *target_addr;
        let payload = payload.clone();
        client_tasks
            .spawn(async move { assert_echo_roundtrip(socks_addr, target_addr, &payload).await });
    }
    while let Some(result) = client_tasks.join_next().await {
        result??;
    }

    for (_, target_task, payload) in targets {
        assert_eq!(target_task.await??, payload);
    }
    Ok(())
}

async fn run_buffered_limit_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_read_to_eof_target().await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_buffered_bytes_per_flow(1),
    )
    .await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(b"over limit").await?;
    let mut eof = [0_u8; 1];
    assert_eq!(socks.read(&mut eof).await?, 0);

    let target_received = target_task.await??;
    assert!(target_received.is_empty());
    Ok(())
}

async fn run_client_buffered_limit_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = ClientBufferedLimitServerHarness::start().await?;
    let (_socks, connect_reply) = open_socks_connect(
        harness.socks_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
    )
    .await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    assert_eq!(harness.observed_close_code().await?, TCP_CLOSE_ERROR);
    Ok(())
}

async fn run_client_flow_resource_limit_keeps_session_e2e() -> Result<(), TestError> {
    init_tracing();

    let (first_target_addr, first_target_task) = spawn_read_to_eof_target().await?;
    let (second_target_addr, second_target_task) = spawn_echo_target().await?;
    let harness =
        ServerHarness::start_with_policy(test_limits(), Some(allow_loopback_any_port_policy()))
            .await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &tcp_open_frame(1, first_target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;
    write_frame(
        &mut carrier,
        &flow_status_frame(FrameType::ResourceLimit, 1, ErrorCode::ResourceLimit)?,
    )
    .await?;
    write_frame(&mut carrier, &tcp_close_frame(1, TCP_CLOSE_ERROR)?).await?;
    assert!(first_target_task.await??.is_empty());

    write_frame(&mut carrier, &tcp_open_frame(3, second_target_addr)?).await?;
    read_open_ack(&mut carrier, 3).await?;
    let payload = Bytes::from_static(b"session survived client resource limit");
    let data = Frame::new(FrameType::TcpData, 0, 3, payload.clone())?;
    write_frame(&mut carrier, &data).await?;

    let echoed = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(echoed.header.frame_type, FrameType::TcpData);
    assert_eq!(echoed.header.id, 3);
    assert_eq!(echoed.payload, payload);

    write_frame(&mut carrier, &tcp_close_frame(3, TCP_CLOSE_NORMAL)?).await?;
    second_target_task.await??;
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

async fn run_half_close_timeout_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) =
        spawn_write_shutdown_then_read_target(TARGET_HALF_CLOSE_TIMEOUT_GREETING).await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_half_close_timeout(1),
    )
    .await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    let mut greeting = vec![0_u8; TARGET_HALF_CLOSE_TIMEOUT_GREETING.len()];
    socks.read_exact(&mut greeting).await?;
    assert_eq!(greeting, TARGET_HALF_CLOSE_TIMEOUT_GREETING);
    let mut eof = [0_u8; 1];
    assert_eq!(socks.read(&mut eof).await?, 0);

    let target_received = target_task.await??;
    assert!(target_received.is_empty());
    Ok(())
}

async fn run_client_half_close_timeout_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, release_target, target_task) =
        spawn_read_to_eof_until_released_target().await?;
    let harness = RelayHarness::start_with_limits(
        Some(allow_loopback_policy(target_addr.port())),
        test_limits_with_half_close_timeout(1),
    )
    .await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(HALF_CLOSE_REQUEST).await?;
    socks.shutdown().await?;

    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), socks.read(&mut byte)).await??;
    assert_eq!(read, 0);

    let _ = release_target.send(());
    let target_received = target_task.await??;
    assert_eq!(target_received, HALF_CLOSE_REQUEST);
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

    socks.write_all(b"Uncrowned King domain e2e").await?;
    let mut echoed = vec![0_u8; "Uncrowned King domain e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"Uncrowned King domain e2e");

    echo_task.await??;
    Ok(())
}

async fn run_policy_group_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_default_group_loopback_policy(
        target_addr.port(),
    )))
    .await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(b"Uncrowned King policy group e2e").await?;
    let mut echoed = vec![0_u8; "Uncrowned King policy group e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"Uncrowned King policy group e2e");

    echo_task.await??;
    Ok(())
}

async fn run_policy_group_mismatch_e2e() -> Result<(), TestError> {
    init_tracing();

    let denied_target = unused_loopback_addr().await?;
    let harness = RelayHarness::start(Some(allow_admin_group_loopback_policy(
        denied_target.port(),
    )))
    .await?;

    let (_socks, connect_reply) = open_socks_connect(harness.socks_addr, denied_target).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_NOT_ALLOWED);
    Ok(())
}

async fn run_ipv6_relay_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_ipv6_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_ipv6_loopback_policy(target_addr.port()))).await?;

    let (mut socks, connect_reply) = open_socks_connect(harness.socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(b"Uncrowned King ipv6 e2e").await?;
    let mut echoed = vec![0_u8; "Uncrowned King ipv6 e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"Uncrowned King ipv6 e2e");

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

async fn run_auth_failure_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let result = run_handshake(harness.client_config(WRONG_SECRET)).await;

    let error = result.expect_err("wrong secret must fail authentication");
    assert!(
        error.to_string().contains("authentication failed"),
        "unexpected auth failure error: {error}"
    );
    Ok(())
}

async fn run_handshake_fallback_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let unused_primary = unused_loopback_addr().await?;
    let mut config = harness.client_config(SECRET);
    config.server_addr = unused_primary.to_string();
    config.server_addrs = Some(vec![harness.server_addr.to_string()]);

    run_handshake(config).await?;
    Ok(())
}

async fn run_handshake_timeout_fallback_e2e() -> Result<(), TestError> {
    init_tracing();

    let primary_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let primary_addr = primary_listener.local_addr()?;
    let silent_primary = tokio::spawn(async move {
        let (_stream, _) = primary_listener.accept().await?;
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok::<(), TestError>(())
    });

    let harness = ServerHarness::start(test_limits()).await?;
    let mut config = harness.client_config(SECRET);
    config.server_addr = primary_addr.to_string();
    config.server_addrs = Some(vec![harness.server_addr.to_string()]);
    config.handshake_timeout_seconds = Some(1);

    run_handshake(config).await?;
    silent_primary.abort();
    Ok(())
}

async fn run_all_handshake_endpoints_failed_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let primary = unused_loopback_addr().await?;
    let fallback = unused_loopback_addr().await?;
    let mut config = harness.client_config(SECRET);
    config.server_addr = primary.to_string();
    config.server_addrs = Some(vec![fallback.to_string()]);
    config.handshake_timeout_seconds = Some(1);

    let error = run_handshake(config)
        .await
        .expect_err("all unavailable handshake endpoints must fail");
    let text = error.to_string();

    assert!(
        text.contains("2 endpoint attempt"),
        "error did not report both endpoint attempts: {text}"
    );
    assert!(
        text.contains(&format!("[0] {primary}: tcp connect failed")),
        "error did not include primary endpoint failure: {text}"
    );
    assert!(
        text.contains(&format!("[1] {fallback}: tcp connect failed")),
        "error did not include fallback endpoint failure: {text}"
    );
    Ok(())
}

async fn run_expired_auth_challenge_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start_with_auth_skew(test_limits(), None, 0).await?;
    let mut carrier = connect_tls_carrier(&harness).await?;
    let exporter = client_exporter(&carrier)?;

    let challenge_frame = read_frame(&mut carrier, FrameLimits::default()).await?;
    validate_connection_frame(&challenge_frame, FrameType::AuthChallenge)?;
    let mut challenge_payload = challenge_frame.payload;
    let challenge = AuthChallenge::decode(&mut challenge_payload)?;

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let response = AuthResponse::for_challenge(
        KEY_ID.as_bytes(),
        SECRET.as_bytes(),
        &exporter,
        &challenge,
        unix_now(),
        Vec::new(),
    )?;
    let mut response_payload = BytesMut::new();
    response.encode(&mut response_payload)?;
    let response_frame = Frame::new(FrameType::AuthResponse, 0, 0, response_payload.freeze())?;
    write_frame(&mut carrier, &response_frame).await?;

    let error_frame = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(error_frame.header.frame_type, FrameType::Error);
    assert_eq!(error_frame.header.id, 0);

    let mut payload = error_frame.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::AuthFailed
    );
    Ok(())
}

async fn run_oversized_auth_response_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let mut carrier = connect_tls_carrier(&harness).await?;

    let challenge = read_frame(&mut carrier, FrameLimits::default()).await?;
    assert_eq!(challenge.header.frame_type, FrameType::AuthChallenge);
    assert_eq!(challenge.header.id, 0);

    write_oversized_frame_header(
        &mut carrier,
        FrameType::AuthResponse,
        0,
        test_limits().max_pre_auth_bytes.unwrap(),
    )
    .await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 0);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::OversizedFrame
    );
    Ok(())
}

async fn run_unexpected_auth_response_frame_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let mut carrier = connect_tls_carrier(&harness).await?;

    let challenge = read_frame(&mut carrier, FrameLimits::default()).await?;
    assert_eq!(challenge.header.frame_type, FrameType::AuthChallenge);
    assert_eq!(challenge.header.id, 0);

    let frame = Frame::new(FrameType::Settings, 0, 0, Bytes::new())?;
    write_frame(&mut carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 0);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::Protocol
    );
    Ok(())
}

async fn run_zero_id_tcp_close_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let mut payload = BytesMut::new();
    TcpClose::new(TCP_CLOSE_NORMAL).encode(&mut payload)?;
    let frame = Frame::new(FrameType::TcpClose, 0, 0, payload.freeze())?;
    write_frame(&mut carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 0);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::Protocol
    );
    Ok(())
}

async fn run_zero_id_udp_close_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let frame = udp_close_frame(0, UDP_CLOSE_NORMAL)?;
    write_frame(&mut carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 0);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::Protocol
    );
    Ok(())
}

async fn run_malformed_tcp_close_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let frame = Frame::new(FrameType::TcpClose, 0, 1, Bytes::new())?;
    write_frame(&mut carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 1);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::Protocol
    );
    Ok(())
}

async fn run_malformed_udp_close_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let frame = Frame::new(FrameType::UdpClose, 0, 1, Bytes::new())?;
    write_frame(&mut carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 1);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::Protocol
    );
    Ok(())
}

async fn run_malformed_tcp_open_flags_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;
    let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    let frame = malformed_tcp_open_flags_frame(1, target_addr)?;

    write_frame(&mut carrier, &frame).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;
    assert_tcp_close(&mut carrier, 1, TCP_CLOSE_ERROR).await?;
    Ok(())
}

async fn run_malformed_udp_open_target_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &malformed_udp_open_target_frame(1)?).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::InvalidTarget).await?;
    assert_udp_close(&mut carrier, 1, UDP_CLOSE_ERROR).await?;
    Ok(())
}

async fn run_duplicate_tcp_open_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_read_to_eof_target().await?;
    let harness = ServerHarness::start_with_policy(
        test_limits(),
        Some(allow_loopback_policy(target_addr.port())),
    )
    .await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &tcp_open_frame(1, target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;

    write_frame(&mut carrier, &tcp_open_frame(1, target_addr)?).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 1);
    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::Protocol
    );

    let close = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(close.header.frame_type, FrameType::TcpClose);
    assert_eq!(close.header.id, 1);
    let mut payload = close.payload;
    assert_eq!(TcpClose::decode(&mut payload)?.close_code, TCP_CLOSE_ERROR);

    let target_received = tokio::time::timeout(Duration::from_secs(3), target_task).await???;
    assert!(target_received.is_empty());
    Ok(())
}

async fn run_duplicate_udp_open_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_udp_echo_target().await?;
    let harness = ServerHarness::start_with_policy(
        test_limits(),
        Some(allow_loopback_policy(target_addr.port())),
    )
    .await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &udp_open_frame(1, target_addr)?).await?;
    read_udp_open_ack(&mut carrier, 1).await?;

    write_frame(&mut carrier, &udp_open_frame(1, target_addr)?).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;

    let close = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(close.header.frame_type, FrameType::UdpClose);
    assert_eq!(close.header.id, 1);
    let mut payload = close.payload;
    assert_eq!(UdpClose::decode(&mut payload)?.close_code, UDP_CLOSE_ERROR);

    let data = Frame::new(
        FrameType::UdpData,
        0,
        1,
        Bytes::from_static(b"duplicate udp open must close old slot"),
    )?;
    write_frame(&mut carrier, &data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;

    target_task.abort();
    Ok(())
}

async fn run_wrong_protocol_udp_close_on_tcp_flow_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_read_to_eof_target().await?;
    let harness = ServerHarness::start_with_policy(
        test_limits(),
        Some(allow_loopback_policy(target_addr.port())),
    )
    .await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &tcp_open_frame(1, target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;

    write_frame(&mut carrier, &udp_close_frame(1, UDP_CLOSE_ERROR)?).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;
    assert_tcp_close(&mut carrier, 1, TCP_CLOSE_ERROR).await?;

    let data = Frame::new(
        FrameType::TcpData,
        0,
        1,
        Bytes::from_static(b"tcp flow should be gone"),
    )?;
    write_frame(&mut carrier, &data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;

    let target_received = tokio::time::timeout(Duration::from_secs(3), target_task).await???;
    assert!(target_received.is_empty());
    Ok(())
}

async fn run_wrong_protocol_tcp_close_on_udp_flow_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_udp_echo_target().await?;
    let harness = ServerHarness::start_with_policy(
        test_limits(),
        Some(allow_loopback_policy(target_addr.port())),
    )
    .await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &udp_open_frame(1, target_addr)?).await?;
    read_udp_open_ack(&mut carrier, 1).await?;

    write_frame(&mut carrier, &tcp_close_frame(1, TCP_CLOSE_ERROR)?).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;
    assert_udp_close(&mut carrier, 1, UDP_CLOSE_ERROR).await?;

    let data = Frame::new(
        FrameType::UdpData,
        0,
        1,
        Bytes::from_static(b"udp flow should be gone"),
    )?;
    write_frame(&mut carrier, &data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;

    target_task.abort();
    Ok(())
}

async fn run_wrong_protocol_udp_data_on_tcp_flow_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_read_to_eof_target().await?;
    let harness = ServerHarness::start_with_policy(
        test_limits(),
        Some(allow_loopback_policy(target_addr.port())),
    )
    .await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &tcp_open_frame(1, target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;

    let wrong_data = Frame::new(
        FrameType::UdpData,
        0,
        1,
        Bytes::from_static(b"wrong udp data"),
    )?;
    write_frame(&mut carrier, &wrong_data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;
    assert_tcp_close(&mut carrier, 1, TCP_CLOSE_ERROR).await?;

    let data = Frame::new(
        FrameType::TcpData,
        0,
        1,
        Bytes::from_static(b"tcp flow should be gone"),
    )?;
    write_frame(&mut carrier, &data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;

    let target_received = tokio::time::timeout(Duration::from_secs(3), target_task).await???;
    assert!(target_received.is_empty());
    Ok(())
}

async fn run_wrong_protocol_tcp_data_on_udp_flow_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, target_task) = spawn_udp_echo_target().await?;
    let harness = ServerHarness::start_with_policy(
        test_limits(),
        Some(allow_loopback_policy(target_addr.port())),
    )
    .await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &udp_open_frame(1, target_addr)?).await?;
    read_udp_open_ack(&mut carrier, 1).await?;

    let wrong_data = Frame::new(
        FrameType::TcpData,
        0,
        1,
        Bytes::from_static(b"wrong tcp data"),
    )?;
    write_frame(&mut carrier, &wrong_data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;
    assert_udp_close(&mut carrier, 1, UDP_CLOSE_ERROR).await?;

    let data = Frame::new(
        FrameType::UdpData,
        0,
        1,
        Bytes::from_static(b"udp flow should be gone"),
    )?;
    write_frame(&mut carrier, &data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;

    target_task.abort();
    Ok(())
}

async fn run_unknown_tcp_data_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let data = Frame::new(
        FrameType::TcpData,
        0,
        1,
        Bytes::from_static(b"orphan tcp data"),
    )?;
    write_frame(&mut carrier, &data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;

    write_ping_expect_pong(
        &mut carrier,
        Bytes::from_static(b"session survives unknown tcp flow"),
    )
    .await?;
    Ok(())
}

async fn run_unknown_udp_data_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let data = Frame::new(
        FrameType::UdpData,
        0,
        1,
        Bytes::from_static(b"orphan udp data"),
    )?;
    write_frame(&mut carrier, &data).await?;
    assert_flow_error(&mut carrier, 1, ErrorCode::Protocol).await?;

    write_ping_expect_pong(
        &mut carrier,
        Bytes::from_static(b"session survives unknown udp flow"),
    )
    .await?;
    Ok(())
}

async fn run_reserved_flow_id_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_frame(&mut carrier, &tcp_open_frame(2, target_addr)?).await?;
    assert_flow_error(&mut carrier, 2, ErrorCode::Protocol).await?;
    assert_tcp_close(&mut carrier, 2, TCP_CLOSE_ERROR).await?;

    write_frame(&mut carrier, &udp_open_frame(4, target_addr)?).await?;
    assert_flow_error(&mut carrier, 4, ErrorCode::Protocol).await?;
    assert_udp_close(&mut carrier, 4, UDP_CLOSE_ERROR).await?;
    Ok(())
}

async fn run_oversized_client_frame_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    write_oversized_tcp_data_header(&mut carrier, 1).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 0);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::OversizedFrame
    );
    Ok(())
}

async fn run_unexpected_session_frame_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let frame = Frame::new(FrameType::Settings, 0, 0, Bytes::new())?;
    write_frame(&mut carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 0);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::Protocol
    );
    Ok(())
}

async fn run_malformed_server_relay_frame_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = MalformedFrameServerHarness::start().await?;
    let (_socks, connect_reply) = open_socks_connect(
        harness.socks_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
    )
    .await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    assert_eq!(harness.received_error_code().await?, ErrorCode::Protocol);
    Ok(())
}

async fn run_wrong_protocol_server_frame_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = MalformedFrameServerHarness::start_wrong_protocol_frame().await?;
    let (_socks, connect_reply) = open_socks_connect(
        harness.socks_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
    )
    .await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    assert_eq!(harness.received_error_code().await?, ErrorCode::Protocol);
    Ok(())
}

async fn run_non_empty_open_ack_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = MalformedFrameServerHarness::start_non_empty_open_ack().await?;
    let (_socks, connect_reply) = open_socks_connect(
        harness.socks_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
    )
    .await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_GENERAL_FAILURE);

    assert_eq!(harness.received_error_code().await?, ErrorCode::Protocol);
    Ok(())
}

async fn run_oversized_server_frame_during_open_e2e() -> Result<(), TestError> {
    init_tracing();

    let mut harness = MalformedFrameServerHarness::start_oversized_frame_during_open().await?;
    let (_socks, connect_reply) = open_socks_connect(
        harness.socks_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
    )
    .await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_GENERAL_FAILURE);

    assert_eq!(
        harness.received_error_code().await?,
        ErrorCode::OversizedFrame
    );
    Ok(())
}

async fn run_nonzero_id_ping_error_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let frame = Frame::new(FrameType::Ping, 0, 1, Bytes::new())?;
    write_frame(&mut carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, 0);

    let mut payload = response.payload;
    assert_eq!(
        ErrorPayload::decode(&mut payload)?.code,
        ErrorCode::Protocol
    );
    Ok(())
}

async fn run_authenticated_ping_pong_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits()).await?;
    let (mut carrier, _settings) =
        connect_authenticated_carrier(harness.client_config(SECRET)).await?;

    let payload = Bytes::from_static(b"authenticated-ping");
    let frame = Frame::new(FrameType::Ping, 0, 0, payload.clone())?;
    write_frame(&mut carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Pong);
    assert_eq!(response.header.id, 0);
    assert_eq!(response.payload, payload);
    Ok(())
}

async fn run_server_listener_shutdown_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (_server_addr, server_task) = start_uk_server_until_shutdown(
        test_server_config(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &cert_path,
            &key_path,
            test_limits(),
            None,
            30,
        ),
        async {
            let _ = shutdown_rx.await;
        },
    )
    .await?;

    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}

async fn run_server_observability_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;
    let (tcp_target_addr, tcp_target_task) = spawn_echo_target().await?;
    let (udp_target_addr, udp_target_task) = spawn_udp_echo_target().await?;
    let observability_addr = unused_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut config = test_server_config(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &cert_path,
        &key_path,
        test_limits(),
        Some(&policy_path),
        30,
    );
    config.observability_listen = Some(observability_addr.to_string());
    let (server_addr, mut server_task) = start_uk_server_until_shutdown(config, async {
        let _ = shutdown_rx.await;
    })
    .await?;
    wait_for_listener(
        "uk-server observability",
        observability_addr,
        &mut server_task,
    )
    .await?;

    let health = http_get(observability_addr, "/healthz").await?;
    let ready = http_get(observability_addr, "/readyz").await?;
    assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(ready.starts_with("HTTP/1.1 200 OK\r\n"));

    let (mut carrier, _settings) = connect_authenticated_carrier(ClientConfig {
        server_addr: server_addr.to_string(),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: path_string(&cert_path),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds: Some(3),
        server_connect_retry_delay_millis: None,
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: Some(3),
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
    })
    .await?;

    let tcp_payload = Bytes::from_static(b"observability tcp payload");
    write_frame(&mut carrier, &tcp_open_frame(1, tcp_target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;
    write_frame(
        &mut carrier,
        &Frame::new(FrameType::TcpData, 0, 1, tcp_payload.clone())?,
    )
    .await?;
    let tcp_echo = read_relay_frame(&mut carrier, FrameType::TcpData, 1).await?;
    assert_eq!(tcp_echo.payload, tcp_payload);
    tcp_target_task.await??;

    let udp_payload = Bytes::from_static(b"observability udp payload");
    write_frame(&mut carrier, &udp_open_frame(3, udp_target_addr)?).await?;
    read_relay_frame(&mut carrier, FrameType::UdpData, 3).await?;
    write_frame(
        &mut carrier,
        &Frame::new(FrameType::UdpData, 0, 3, udp_payload.clone())?,
    )
    .await?;
    let udp_echo = read_relay_frame(&mut carrier, FrameType::UdpData, 3).await?;
    assert_eq!(udp_echo.payload, udp_payload);
    udp_target_task.await??;

    let metrics = http_get(observability_addr, "/metrics").await?;
    assert_observability_relay_metrics(&metrics, tcp_payload.len(), udp_payload.len());

    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    drop(carrier);
    assert!(TcpStream::connect(observability_addr).await.is_err());
    Ok(())
}

#[tokio::test]
async fn quic_carrier_round_trips_tcp_relay() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;
    let (tcp_target_addr, tcp_target_task) = spawn_echo_target().await?;

    let quic_addr = unused_udp_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut config = test_server_config(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &cert_path,
        &key_path,
        test_limits(),
        Some(&policy_path),
        30,
    );
    config.quic_listen = Some(quic_addr.to_string());
    let (_server_addr, server_task) = start_uk_server_until_shutdown(config, async {
        let _ = shutdown_rx.await;
    })
    .await?;

    let (mut carrier, _settings) = connect_authenticated_carrier(ClientConfig {
        server_addr: format!("quic://{quic_addr}"),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: path_string(&cert_path),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds: Some(5),
        server_connect_retry_delay_millis: None,
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: Some(3),
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
    })
    .await?;

    let tcp_payload = Bytes::from_static(b"quic carrier tcp payload");
    write_frame(&mut carrier, &tcp_open_frame(1, tcp_target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;
    write_frame(
        &mut carrier,
        &Frame::new(FrameType::TcpData, 0, 1, tcp_payload.clone())?,
    )
    .await?;
    let tcp_echo = read_relay_frame(&mut carrier, FrameType::TcpData, 1).await?;
    assert_eq!(tcp_echo.payload, tcp_payload);
    tcp_target_task.await??;

    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(5), server_task).await???;
    drop(carrier);
    Ok(())
}

/// Drives a real SOCKS5 UDP ASSOCIATE round trip over the QUIC carrier, so the
/// UDP data plane exercises native QUIC DATAGRAM on both the client
/// (`send_udp_data`) and server (`relay_udp_target_to_client`) plus the client
/// datagram receiver.
#[tokio::test]
async fn quic_carrier_relays_udp_over_datagram() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_udp_echo_target().await?;

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_policy(target_addr.port()))?;

    let quic_addr = unused_udp_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut config = test_server_config(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &cert_path,
        &key_path,
        test_limits(),
        Some(&policy_path),
        30,
    );
    config.quic_listen = Some(quic_addr.to_string());
    let (_server_addr, server_task) = start_uk_server_until_shutdown(config, async {
        let _ = shutdown_rx.await;
    })
    .await?;

    let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
        server_addr: format!("quic://{quic_addr}"),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: path_string(&cert_path),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds: Some(5),
        server_connect_retry_delay_millis: None,
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: Some(3),
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
    })
    .await?;

    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let payload = b"uncrowned king udp over quic datagram";

    udp_client
        .send_to(&socks_udp_datagram(target_addr, payload), udp_relay_addr)
        .await?;
    let (reply_target, reply_payload) =
        recv_socks_udp_datagram(&udp_client, udp_relay_addr).await?;
    assert_eq!(reply_target, target_addr);
    assert_eq!(reply_payload, payload);

    echo_task.await??;
    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(5), server_task).await???;
    client_task.abort();
    Ok(())
}

/// A UDP payload larger than any QUIC datagram size must fall back to the
/// reliable `UDP_DATA` frame path in both directions and still round-trip.
#[tokio::test]
async fn quic_carrier_falls_back_to_udp_frame_for_large_payload() -> Result<(), TestError> {
    init_tracing();

    // Echo target with a buffer large enough for the oversized payload.
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target_addr = target_socket.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 16_384];
        let (read, peer) = target_socket.recv_from(&mut buf).await?;
        target_socket.send_to(&buf[..read], peer).await?;
        Ok::<(), TestError>(())
    });

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_policy(target_addr.port()))?;

    let quic_addr = unused_udp_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut config = test_server_config(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &cert_path,
        &key_path,
        test_limits(),
        Some(&policy_path),
        30,
    );
    config.quic_listen = Some(quic_addr.to_string());
    let (_server_addr, server_task) = start_uk_server_until_shutdown(config, async {
        let _ = shutdown_rx.await;
    })
    .await?;

    let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
        server_addr: format!("quic://{quic_addr}"),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: path_string(&cert_path),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds: Some(5),
        server_connect_retry_delay_millis: None,
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: Some(3),
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
    })
    .await?;

    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    // 8 KiB exceeds any QUIC datagram size but fits the frame limit.
    let payload = vec![0x5a_u8; 8_000];

    udp_client
        .send_to(&socks_udp_datagram(target_addr, &payload), udp_relay_addr)
        .await?;
    // Receive with a buffer large enough for the oversized reply (the shared
    // helper caps at 1 KiB).
    let mut reply_buf = vec![0_u8; 16_384];
    let (read, peer) =
        tokio::time::timeout(Duration::from_secs(3), udp_client.recv_from(&mut reply_buf))
            .await??;
    assert_eq!(peer, udp_relay_addr);
    let (reply_target, reply_payload) = parse_socks_udp_datagram(&reply_buf[..read])?;
    assert_eq!(reply_target, target_addr);
    assert_eq!(reply_payload, payload);

    echo_task.await??;
    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(5), server_task).await???;
    client_task.abort();
    Ok(())
}

async fn run_client_observability_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;

    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    let (server_addr, server_task) = start_uk_server_until_shutdown(
        test_server_config(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &cert_path,
            &key_path,
            test_limits(),
            Some(&policy_path),
            30,
        ),
        async {
            let _ = server_shutdown_rx.await;
        },
    )
    .await?;

    let observability_addr = unused_loopback_addr().await?;
    let unavailable_primary = unused_loopback_addr().await?;
    let mut initial_config = test_client_config(server_addr, &cert_path, SECRET);
    initial_config.server_addr = unavailable_primary.to_string();
    initial_config.server_addrs = Some(vec![server_addr.to_string()]);
    initial_config.observability_listen = Some(observability_addr.to_string());
    let ReloadableSocksListener {
        socks_addr,
        reload_handle,
        shutdown_tx: client_shutdown_tx,
        mut task,
    } = start_reloadable_socks5_listener(initial_config.clone()).await?;
    wait_for_listener("uk-client observability", observability_addr, &mut task).await?;

    let health = http_get(observability_addr, "/healthz").await?;
    let ready = http_get(observability_addr, "/readyz").await?;
    assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(ready.starts_with("HTTP/1.1 200 OK\r\n"));

    let (udp_target_addr, udp_target_task) = spawn_udp_echo_target().await?;
    let (udp_control, udp_relay_addr) = open_socks_udp_associate(socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let udp_payload = b"client observability udp payload";
    assert_socks_udp_roundtrip(&udp_client, udp_relay_addr, udp_target_addr, udp_payload).await?;
    udp_target_task.await??;

    let mut incompatible = initial_config.clone();
    incompatible.observability_listen = Some(unused_loopback_addr().await?.to_string());
    assert!(matches!(
        reload_handle.reload(incompatible).await.unwrap_err(),
        ClientReloadError::Rejected(reason) if reason.contains("observability_listen")
    ));
    let mut reloaded = initial_config;
    reloaded.tcp_open_timeout_seconds = Some(4);
    assert_eq!(reload_handle.reload(reloaded).await?, 2);
    wait_for_client_metric(
        observability_addr,
        "uncrowned_king_client_draining_sessions 1\n",
    )
    .await?;

    let (tcp_target_addr, tcp_target_task) = spawn_echo_target().await?;
    let tcp_payload = b"client observability tcp payload";
    assert_echo_roundtrip(socks_addr, tcp_target_addr, tcp_payload).await?;
    tcp_target_task.await??;
    wait_for_client_metric(
        observability_addr,
        "uncrowned_king_client_active_sessions 2\n",
    )
    .await?;

    let metrics = http_get(observability_addr, "/metrics").await?;
    assert_client_observability_metrics(&metrics, tcp_payload.len(), udp_payload.len());

    drop(udp_control);
    wait_for_client_metric(
        observability_addr,
        "uncrowned_king_client_draining_sessions 0\n",
    )
    .await?;
    wait_for_client_metric(
        observability_addr,
        "uncrowned_king_client_active_sessions 1\n",
    )
    .await?;

    client_shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    assert!(TcpStream::connect(observability_addr).await.is_err());
    server_shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    let _ = fs::remove_dir_all(temp_dir);
    Ok(())
}

async fn run_server_access_control_reload_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;
    let (target_addr, target_task) = spawn_echo_target().await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = listener.local_addr()?;
    let config = test_server_config(
        server_addr,
        &cert_path,
        &key_path,
        test_limits(),
        Some(&policy_path),
        30,
    );
    let mut candidate = config.clone();
    candidate.policy_path = None;
    WRONG_SECRET.clone_into(&mut candidate.credentials[0].secret);
    let mut incompatible_candidate = candidate.clone();
    "127.0.0.1:1".clone_into(&mut incompatible_candidate.listen);
    let mut disabled_candidate = candidate.clone();
    disabled_candidate.policy_path = Some(path_string(&policy_path));
    disabled_candidate.credentials[0].status = Some("disabled".to_owned());
    let (reload_handle, reload_rx) = server_reload_channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(run_on_listener_until_shutdown_with_reload(
        config,
        listener,
        reload_rx,
        async {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-server", server_addr, &mut server_task).await?;

    let (mut carrier, _settings) =
        connect_authenticated_carrier(test_client_config(server_addr, &cert_path, SECRET)).await?;
    write_frame(&mut carrier, &tcp_open_frame(1, target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;

    let rejection = reload_handle
        .reload(incompatible_candidate)
        .await
        .unwrap_err();
    assert!(matches!(
        rejection,
        ServerReloadError::Rejected(reason)
            if reason.contains("listen") && reason.contains("requires a restart")
    ));
    assert_eq!(reload_handle.reload(candidate).await?, 2);

    let payload = Bytes::from_static(b"existing flow survives access-control reload");
    write_frame(
        &mut carrier,
        &Frame::new(FrameType::TcpData, 0, 1, payload.clone())?,
    )
    .await?;
    let echoed = read_relay_frame(&mut carrier, FrameType::TcpData, 1).await?;
    assert_eq!(echoed.payload, payload);
    target_task.await??;

    write_frame(&mut carrier, &tcp_open_frame(3, target_addr)?).await?;
    let denied = read_relay_frame(&mut carrier, FrameType::PolicyDenied, 3).await?;
    let mut denied_payload = denied.payload;
    assert_eq!(
        ErrorPayload::decode(&mut denied_payload)?.code,
        ErrorCode::PolicyDenied
    );
    assert_tcp_close(&mut carrier, 3, TCP_CLOSE_NORMAL).await?;

    assert!(
        connect_authenticated_carrier(test_client_config(server_addr, &cert_path, SECRET))
            .await
            .is_err()
    );
    let (rotated_carrier, _settings) =
        connect_authenticated_carrier(test_client_config(server_addr, &cert_path, WRONG_SECRET))
            .await?;

    assert_eq!(reload_handle.reload(disabled_candidate).await?, 3);
    write_frame(&mut carrier, &tcp_open_frame(5, target_addr)?).await?;
    let revoked = read_relay_frame(&mut carrier, FrameType::PolicyDenied, 5).await?;
    let mut revoked_payload = revoked.payload;
    assert_eq!(
        ErrorPayload::decode(&mut revoked_payload)?.code,
        ErrorCode::PolicyDenied
    );
    assert_tcp_close(&mut carrier, 5, TCP_CLOSE_NORMAL).await?;

    drop(carrier);
    drop(rotated_carrier);
    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    let _ = fs::remove_dir_all(temp_dir);
    Ok(())
}

async fn run_server_tls_identity_reload_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let server_cert_path = temp_dir.join("server-cert.pem");
    let server_key_path = temp_dir.join("server-key.pem");
    let initial_ca_path = temp_dir.join("initial-ca.pem");
    let rotated_ca_path = temp_dir.join("rotated-ca.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&server_cert_path, CERT_PEM)?;
    write_private_key(&server_key_path)?;
    fs::write(&initial_ca_path, CERT_PEM)?;
    fs::write(&rotated_ca_path, ROTATED_CERT_PEM)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;

    let (target_addr, target_task) = spawn_echo_target().await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = listener.local_addr()?;
    let config = test_server_config(
        server_addr,
        &server_cert_path,
        &server_key_path,
        test_limits(),
        Some(&policy_path),
        30,
    );
    let reload_config = config.clone();
    let (reload_handle, reload_rx) = server_reload_channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(run_on_listener_until_shutdown_with_reload(
        config,
        listener,
        reload_rx,
        async {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-server", server_addr, &mut server_task).await?;

    let (mut carrier, _settings) =
        connect_authenticated_carrier(test_client_config(server_addr, &initial_ca_path, SECRET))
            .await?;
    write_frame(&mut carrier, &tcp_open_frame(1, target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;

    fs::write(&server_cert_path, ROTATED_CERT_PEM)?;
    let rejection = reload_handle
        .reload(reload_config.clone())
        .await
        .unwrap_err();
    assert!(matches!(rejection, ServerReloadError::Rejected(reason) if !reason.is_empty()));

    let (rollback_carrier, _settings) =
        connect_authenticated_carrier(test_client_config(server_addr, &initial_ca_path, SECRET))
            .await?;
    drop(rollback_carrier);

    write_private_key_contents(&server_key_path, ROTATED_KEY_PEM)?;
    assert_eq!(reload_handle.reload(reload_config).await?, 2);

    let payload = Bytes::from_static(b"existing flow survives TLS identity rotation");
    write_frame(
        &mut carrier,
        &Frame::new(FrameType::TcpData, 0, 1, payload.clone())?,
    )
    .await?;
    let echoed = read_relay_frame(&mut carrier, FrameType::TcpData, 1).await?;
    assert_eq!(echoed.payload, payload);
    target_task.await??;

    assert!(
        connect_authenticated_carrier(test_client_config(server_addr, &initial_ca_path, SECRET,))
            .await
            .is_err()
    );
    let (rotated_carrier, _settings) =
        connect_authenticated_carrier(test_client_config(server_addr, &rotated_ca_path, SECRET))
            .await?;

    drop(carrier);
    drop(rotated_carrier);
    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    let _ = fs::remove_dir_all(temp_dir);
    Ok(())
}

async fn run_server_quic_identity_reload_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let server_cert_path = temp_dir.join("server-cert.pem");
    let server_key_path = temp_dir.join("server-key.pem");
    let initial_ca_path = temp_dir.join("initial-ca.pem");
    let rotated_ca_path = temp_dir.join("rotated-ca.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&server_cert_path, CERT_PEM)?;
    write_private_key(&server_key_path)?;
    fs::write(&initial_ca_path, CERT_PEM)?;
    fs::write(&rotated_ca_path, ROTATED_CERT_PEM)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;

    let (target_addr, target_task) = spawn_echo_target().await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = listener.local_addr()?;
    let quic_addr = unused_udp_loopback_addr().await?;
    let mut config = test_server_config(
        server_addr,
        &server_cert_path,
        &server_key_path,
        test_limits(),
        Some(&policy_path),
        30,
    );
    config.quic_listen = Some(quic_addr.to_string());
    let reload_config = config.clone();
    let (reload_handle, reload_rx) = server_reload_channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(run_on_listener_until_shutdown_with_reload(
        config,
        listener,
        reload_rx,
        async {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-server", server_addr, &mut server_task).await?;

    // Establish a QUIC session and open a flow before rotation.
    let (mut carrier, _settings) =
        connect_authenticated_carrier(quic_test_client_config(quic_addr, &initial_ca_path, SECRET))
            .await?;
    write_frame(&mut carrier, &tcp_open_frame(1, target_addr)?).await?;
    read_open_ack(&mut carrier, 1).await?;

    // Rotate cert and key together, then reload atomically.
    fs::write(&server_cert_path, ROTATED_CERT_PEM)?;
    write_private_key_contents(&server_key_path, ROTATED_KEY_PEM)?;
    assert_eq!(reload_handle.reload(reload_config).await?, 2);

    // The pre-rotation QUIC connection keeps working.
    let payload = Bytes::from_static(b"existing quic flow survives identity rotation");
    write_frame(
        &mut carrier,
        &Frame::new(FrameType::TcpData, 0, 1, payload.clone())?,
    )
    .await?;
    let echoed = read_relay_frame(&mut carrier, FrameType::TcpData, 1).await?;
    assert_eq!(echoed.payload, payload);
    target_task.await??;

    // New QUIC connections now present the rotated identity: the old CA is
    // rejected and the rotated CA succeeds.
    assert!(
        connect_authenticated_carrier(quic_test_client_config(quic_addr, &initial_ca_path, SECRET))
            .await
            .is_err()
    );
    let (rotated_carrier, _settings) =
        connect_authenticated_carrier(quic_test_client_config(quic_addr, &rotated_ca_path, SECRET))
            .await?;

    drop(carrier);
    drop(rotated_carrier);
    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    let _ = fs::remove_dir_all(temp_dir);
    Ok(())
}

async fn run_client_connection_config_reload_e2e() -> Result<(), TestError> {
    let temp_dir = create_temp_dir()?;
    let server_cert_path = temp_dir.join("server-cert.pem");
    let server_key_path = temp_dir.join("server-key.pem");
    let initial_ca_path = temp_dir.join("initial-ca.pem");
    let rotated_ca_path = temp_dir.join("rotated-ca.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&server_cert_path, CERT_PEM)?;
    write_private_key(&server_key_path)?;
    fs::write(&initial_ca_path, CERT_PEM)?;
    fs::write(&rotated_ca_path, ROTATED_CERT_PEM)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;

    let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = server_listener.local_addr()?;
    let observability_addr = unused_loopback_addr().await?;
    let mut initial_server_config = test_server_config(
        server_addr,
        &server_cert_path,
        &server_key_path,
        test_limits(),
        Some(&policy_path),
        30,
    );
    initial_server_config.observability_listen = Some(observability_addr.to_string());
    let mut rotated_server_config = initial_server_config.clone();
    WRONG_SECRET.clone_into(&mut rotated_server_config.credentials[0].secret);
    let (server_reload_handle, server_reload_rx) = server_reload_channel();
    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(run_on_listener_until_shutdown_with_reload(
        initial_server_config,
        server_listener,
        server_reload_rx,
        async {
            let _ = server_shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-server", server_addr, &mut server_task).await?;

    let initial_client_config = test_client_config(server_addr, &initial_ca_path, SECRET);
    let mut rotated_client_config = initial_client_config.clone();
    rotated_client_config.ca_cert_path = path_string(&rotated_ca_path);
    WRONG_SECRET.clone_into(&mut rotated_client_config.secret);
    let ReloadableSocksListener {
        socks_addr,
        reload_handle,
        shutdown_tx: client_shutdown_tx,
        task: client_task,
    } = start_reloadable_socks5_listener(initial_client_config.clone()).await?;

    let (old_target_addr, old_target_task) = spawn_echo_target().await?;
    let (mut old_socks, connect_reply) = open_socks_connect(socks_addr, old_target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);
    let mut udp_probe = UdpReloadProbe::start(socks_addr).await?;

    assert_client_reload_rejections(
        &reload_handle,
        &initial_client_config,
        &rotated_client_config,
        &temp_dir,
    )
    .await?;
    fs::write(&server_cert_path, ROTATED_CERT_PEM)?;
    write_private_key_contents(&server_key_path, ROTATED_KEY_PEM)?;
    assert_eq!(server_reload_handle.reload(rotated_server_config).await?, 2);
    assert_eq!(reload_handle.reload(rotated_client_config).await?, 2);

    let (rotated_target_addr, rotated_target_task) = spawn_echo_target().await?;
    assert_echo_roundtrip(
        socks_addr,
        rotated_target_addr,
        b"new flow immediately uses reloaded client carrier",
    )
    .await?;
    rotated_target_task.await??;
    udp_probe.verify_after_reload().await?;
    wait_for_active_server_sessions(observability_addr, 2).await?;

    let payload = b"existing SOCKS flow survives client config reload";
    old_socks.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    old_socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, payload);
    old_target_task.await??;
    drop(old_socks);
    wait_for_active_server_sessions(observability_addr, 2).await?;
    drop(udp_probe);
    wait_for_active_server_sessions(observability_addr, 1).await?;

    server_shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    client_shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    tokio::time::timeout(Duration::from_secs(3), client_task).await???;
    let _ = fs::remove_dir_all(temp_dir);
    Ok(())
}

async fn assert_client_reload_rejections(
    reload_handle: &ClientReloadHandle,
    initial: &ClientConfig,
    rotated: &ClientConfig,
    temp_dir: &Path,
) -> Result<(), TestError> {
    let mut incompatible = initial.clone();
    incompatible.max_socks_connections = Some(initial.max_socks_connections() + 1);
    let rejection = reload_handle.reload(incompatible).await.unwrap_err();
    assert!(matches!(
        rejection,
        ClientReloadError::Rejected(reason)
            if reason.contains("max_socks_connections")
                && reason.contains("requires a restart")
    ));

    let mut invalid_ca = rotated.clone();
    invalid_ca.ca_cert_path = path_string(&temp_dir.join("missing-ca.pem"));
    assert!(matches!(
        reload_handle.reload(invalid_ca).await.unwrap_err(),
        ClientReloadError::Rejected(reason) if reason.contains("missing-ca.pem")
    ));
    Ok(())
}

async fn run_client_reload_during_handshake_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let policy_path = temp_dir.join("policy.toml");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    fs::write(&policy_path, allow_loopback_any_port_policy())?;

    let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = server_listener.local_addr()?;
    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(uk_server::run_on_listener_until_shutdown(
        test_server_config(
            server_addr,
            &cert_path,
            &key_path,
            test_limits(),
            Some(&policy_path),
            30,
        ),
        server_listener,
        async {
            let _ = server_shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-server", server_addr, &mut server_task).await?;

    let stalled_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let stalled_addr = stalled_listener.local_addr()?;
    let (stalled_accepted_tx, stalled_accepted_rx) = oneshot::channel();
    let (release_stalled_tx, release_stalled_rx) = oneshot::channel();
    let stalled_task = tokio::spawn(async move {
        let (stream, _) = stalled_listener.accept().await?;
        stalled_accepted_tx
            .send(())
            .map_err(|()| "stalled handshake observer dropped")?;
        let _ = release_stalled_rx.await;
        drop(stream);
        Ok::<(), TestError>(())
    });

    let mut initial_config = test_client_config(stalled_addr, &cert_path, SECRET);
    initial_config.handshake_timeout_seconds = Some(30);
    let mut reloaded_config = initial_config.clone();
    reloaded_config.server_addr = server_addr.to_string();
    let ReloadableSocksListener {
        socks_addr,
        reload_handle,
        shutdown_tx: client_shutdown_tx,
        task: client_task,
    } = start_reloadable_socks5_listener(initial_config).await?;

    let (target_addr, target_task) = spawn_echo_target().await?;
    let socks_task = tokio::spawn(open_socks_connect(socks_addr, target_addr));
    stalled_accepted_rx.await?;
    assert_eq!(reload_handle.reload(reloaded_config).await?, 2);
    release_stalled_tx
        .send(())
        .map_err(|()| "stalled handshake release receiver dropped")?;

    let (mut socks, connect_reply) = socks_task.await??;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);
    let payload = b"in-flight handshake switches to reloaded client config";
    socks.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, payload);
    target_task.await??;
    stalled_task.await??;

    server_shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    client_shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    tokio::time::timeout(Duration::from_secs(3), client_task).await???;
    let _ = fs::remove_dir_all(temp_dir);
    Ok(())
}

fn assert_observability_relay_metrics(metrics: &str, tcp_bytes: usize, udp_bytes: usize) {
    assert!(metrics.contains("uncrowned_king_server_ready 1\n"));
    assert!(metrics.contains("uncrowned_king_server_security_generation 1\n"));
    assert!(metrics.contains("uncrowned_king_server_authenticated_sessions_total 1\n"));
    assert!(metrics.contains("uncrowned_king_server_active_sessions 1\n"));
    assert!(
        metrics.contains("uncrowned_king_server_flow_open_requests_total{protocol=\"tcp\"} 1\n")
    );
    assert!(metrics.contains("uncrowned_king_server_opened_flows_total{protocol=\"tcp\"} 1\n"));
    assert!(metrics.contains(
        &format!(
            "uncrowned_king_server_relay_bytes_total{{protocol=\"tcp\",direction=\"client_to_target\"}} {tcp_bytes}\n"
        )
    ));
    assert!(metrics.contains(
        &format!(
            "uncrowned_king_server_relay_bytes_total{{protocol=\"tcp\",direction=\"target_to_client\"}} {tcp_bytes}\n"
        )
    ));
    assert!(
        metrics.contains("uncrowned_king_server_flow_open_requests_total{protocol=\"udp\"} 1\n")
    );
    assert!(metrics.contains("uncrowned_king_server_opened_flows_total{protocol=\"udp\"} 1\n"));
    assert!(metrics.contains(
        &format!(
            "uncrowned_king_server_relay_bytes_total{{protocol=\"udp\",direction=\"client_to_target\"}} {udp_bytes}\n"
        )
    ));
    assert!(metrics.contains(
        &format!(
            "uncrowned_king_server_relay_bytes_total{{protocol=\"udp\",direction=\"target_to_client\"}} {udp_bytes}\n"
        )
    ));
}

fn assert_client_observability_metrics(metrics: &str, tcp_bytes: usize, udp_bytes: usize) {
    assert!(metrics.contains("uncrowned_king_client_ready 1\n"));
    assert!(metrics.contains("uncrowned_king_client_config_generation 2\n"));
    assert!(metrics.contains("uncrowned_king_client_config_reload_attempts_total 2\n"));
    assert!(metrics.contains("uncrowned_king_client_config_reload_successes_total 1\n"));
    assert!(metrics.contains("uncrowned_king_client_config_reload_failures_total 1\n"));
    assert!(metrics.contains("uncrowned_king_client_session_connect_attempts_total 2\n"));
    assert!(
        metrics.contains("uncrowned_king_client_endpoint_attempts_total{outcome=\"success\"} 2\n")
    );
    assert!(
        metrics.contains("uncrowned_king_client_endpoint_attempts_total{outcome=\"failure\"} 2\n")
    );
    assert!(metrics.contains("uncrowned_king_client_endpoint_failures_total{phase=\"tcp\"} 2\n"));
    assert!(metrics.contains("uncrowned_king_client_established_sessions_total 2\n"));
    assert!(metrics.contains("uncrowned_king_client_active_sessions 2\n"));
    assert!(metrics.contains("uncrowned_king_client_draining_sessions 1\n"));
    assert!(metrics.contains("uncrowned_king_client_opened_flows_total{protocol=\"tcp\"} 1\n"));
    assert!(metrics.contains("uncrowned_king_client_opened_flows_total{protocol=\"udp\"} 1\n"));
    assert!(metrics.contains(&format!(
        "uncrowned_king_client_relay_bytes_total{{protocol=\"tcp\",direction=\"local_to_server\"}} {tcp_bytes}\n"
    )));
    assert!(metrics.contains(&format!(
        "uncrowned_king_client_relay_bytes_total{{protocol=\"tcp\",direction=\"server_to_local\"}} {tcp_bytes}\n"
    )));
    assert!(metrics.contains(&format!(
        "uncrowned_king_client_relay_bytes_total{{protocol=\"udp\",direction=\"local_to_server\"}} {udp_bytes}\n"
    )));
    assert!(metrics.contains(&format!(
        "uncrowned_king_client_relay_bytes_total{{protocol=\"udp\",direction=\"server_to_local\"}} {udp_bytes}\n"
    )));
}

async fn run_server_active_session_shutdown_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (server_addr, server_task) = start_uk_server_until_shutdown(
        test_server_config(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &cert_path,
            &key_path,
            test_limits(),
            None,
            30,
        ),
        async {
            let _ = shutdown_rx.await;
        },
    )
    .await?;

    let mut carrier = connect_authenticated_carrier(ClientConfig {
        server_addr: server_addr.to_string(),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: path_string(&cert_path),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds: Some(3),
        server_connect_retry_delay_millis: None,
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: None,
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
    })
    .await?
    .0;

    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    let read_result = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await?;
    assert!(matches!(read_result, Err(FrameIoError::Closed)));
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}

async fn run_socks_listener_shutdown_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    fs::write(&cert_path, CERT_PEM)?;
    let server_addr = unused_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (_socks_addr, client_task) = start_socks5_listener_until_shutdown(
        ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        },
        async {
            let _ = shutdown_rx.await;
        },
    )
    .await?;

    shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), client_task).await???;
    Ok(())
}

async fn run_socks_listener_shutdown_cancels_pending_open_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;

    let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = server_listener.local_addr()?;
    let (open_tx, open_rx) = oneshot::channel();
    let server_task = tokio::spawn(run_pending_open_cancel_server_with_signal(
        server_listener,
        cert_path.clone(),
        key_path,
        Some(open_tx),
    ));

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (socks_addr, client_task) = start_socks5_listener_until_shutdown(
        ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(30),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        },
        async {
            let _ = shutdown_rx.await;
        },
    )
    .await?;

    let mut socks = TcpStream::connect(socks_addr).await?;
    let request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
    socks.write_all(&request).await?;
    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    tokio::time::timeout(Duration::from_secs(3), open_rx).await??;

    shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), server_task).await???,
        TCP_CLOSE_ERROR
    );
    tokio::time::timeout(Duration::from_secs(3), client_task).await???;
    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}

async fn run_socks_listener_shutdown_cancels_pending_udp_open_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;

    let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = server_listener.local_addr()?;
    let (open_tx, open_rx) = oneshot::channel();
    let server_task = tokio::spawn(run_pending_udp_open_cancel_server(
        server_listener,
        cert_path.clone(),
        key_path,
        open_tx,
    ));

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (socks_addr, client_task) = start_socks5_listener_until_shutdown(
        ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(30),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        },
        async {
            let _ = shutdown_rx.await;
        },
    )
    .await?;

    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    udp_client
        .send_to(
            &socks_udp_datagram(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                b"pending udp open before shutdown",
            ),
            udp_relay_addr,
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(3), open_rx).await??;

    shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), server_task).await???,
        UDP_CLOSE_ERROR
    );
    tokio::time::timeout(Duration::from_secs(3), client_task).await???;
    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}

async fn run_socks_listener_shutdown_during_connect_e2e() -> Result<(), TestError> {
    run_socks_listener_shutdown_during_connect_with_request(socks_connect_request(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
    ))
    .await
}

async fn run_socks_udp_associate_shutdown_during_connect_e2e() -> Result<(), TestError> {
    run_socks_listener_shutdown_during_connect_with_request(socks_udp_associate_request(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    ))
    .await
}

async fn run_socks_listener_shutdown_during_connect_with_request(
    request: Vec<u8>,
) -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    fs::write(&cert_path, CERT_PEM)?;

    let carrier_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = carrier_listener.local_addr()?;
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let silent_server = tokio::spawn(async move {
        let (_stream, _) = carrier_listener.accept().await?;
        let _ = accepted_tx.send(());
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok::<(), TestError>(())
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (socks_addr, client_task) = start_socks5_listener_until_shutdown(
        ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(30),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(30),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        },
        async {
            let _ = shutdown_rx.await;
        },
    )
    .await?;

    let mut socks = TcpStream::connect(socks_addr).await?;
    socks.write_all(&request).await?;
    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    tokio::time::timeout(Duration::from_secs(3), accepted_rx).await??;

    shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), client_task).await???;
    silent_server.abort();
    Ok(())
}

async fn run_socks_udp_datagram_shutdown_during_reconnect_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;

    let carrier_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = carrier_listener.local_addr()?;
    let server_cert_path = cert_path.clone();
    let server_key_path = key_path.clone();
    let (reconnect_tx, reconnect_rx) = oneshot::channel();
    let silent_reconnect_server = tokio::spawn(async move {
        let first = accept_fake_server_session_from_listener(
            &carrier_listener,
            &server_cert_path,
            &server_key_path,
            fake_server_settings(),
        )
        .await?;
        drop(first);

        let (_tcp, _) = carrier_listener.accept().await?;
        let _ = reconnect_tx.send(());
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok::<(), TestError>(())
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (socks_addr, client_task) = start_socks5_listener_until_shutdown(
        ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(30),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(30),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        },
        async {
            let _ = shutdown_rx.await;
        },
    )
    .await?;

    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    udp_client
        .send_to(
            &socks_udp_datagram(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
                b"trigger udp reconnect",
            ),
            udp_relay_addr,
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(3), reconnect_rx).await??;

    shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), client_task).await???;
    silent_reconnect_server.abort();
    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}

async fn run_udp_carrier_recovery_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM)?;
    write_private_key(&key_path)?;

    let carrier_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = carrier_listener.local_addr()?;
    let (first_closed_tx, first_closed_rx) = oneshot::channel();
    let server_task = tokio::spawn(run_udp_reconnect_server(
        carrier_listener,
        cert_path.clone(),
        key_path,
        first_closed_tx,
    ));
    let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
        server_addr: server_addr.to_string(),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: path_string(&cert_path),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds: Some(3),
        server_connect_retry_delay_millis: Some(0),
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: None,
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
    })
    .await?;

    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
    udp_client
        .send_to(
            &socks_udp_datagram(target, b"first carrier"),
            udp_relay_addr,
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(3), first_closed_rx).await??;

    let recovered_payload = b"recovered carrier";
    let mut recovered = None;
    for _ in 0..20 {
        udp_client
            .send_to(
                &socks_udp_datagram(target, recovered_payload),
                udp_relay_addr,
            )
            .await?;
        if let Ok(result) = tokio::time::timeout(
            Duration::from_millis(100),
            recv_socks_udp_datagram(&udp_client, udp_relay_addr),
        )
        .await
        {
            recovered = Some(result?);
            break;
        }
    }
    let (reply_target, reply_payload) = recovered.ok_or("UDP association did not recover")?;
    assert_eq!(reply_target, target);
    assert_eq!(reply_payload, recovered_payload);

    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    client_task.abort();
    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}

struct ServerHarness {
    temp_dir: PathBuf,
    server_addr: SocketAddr,
    cert_path: PathBuf,
    server_task: JoinHandle<Result<(), TestError>>,
}

impl ServerHarness {
    async fn start(limits: LimitConfig) -> Result<Self, TestError> {
        Self::start_with_policy(limits, None).await
    }

    async fn start_with_policy(
        limits: LimitConfig,
        policy_toml: Option<String>,
    ) -> Result<Self, TestError> {
        Self::start_with_auth_skew(limits, policy_toml, 30).await
    }

    async fn start_with_auth_skew(
        limits: LimitConfig,
        policy_toml: Option<String>,
        auth_skew_seconds: u64,
    ) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;
        let policy_path = if let Some(policy_toml) = policy_toml {
            let policy_path = temp_dir.join("policy.toml");
            fs::write(&policy_path, policy_toml)?;
            Some(policy_path)
        } else {
            None
        };
        let (server_addr, server_task) = start_uk_server(test_server_config(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &cert_path,
            &key_path,
            limits,
            policy_path.as_deref(),
            auth_skew_seconds,
        ))
        .await?;

        Ok(Self {
            temp_dir,
            server_addr,
            cert_path,
            server_task,
        })
    }

    fn client_config(&self, secret: &str) -> ClientConfig {
        ClientConfig {
            server_addr: self.server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&self.cert_path),
            key_id: KEY_ID.to_owned(),
            secret: secret.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        }
    }
}

async fn connect_tls_carrier(
    harness: &ServerHarness,
) -> Result<ClientTlsStream<TcpStream>, TestError> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&harness.cert_path)? {
        roots.add(cert)?;
    }
    let mut config = RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    config.enable_early_data = false;

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("localhost".to_owned())?;
    let tcp = TcpStream::connect(harness.server_addr).await?;
    let stream = connector.connect(server_name, tcp).await?;
    if stream.get_ref().1.alpn_protocol() != Some(ALPN_PROTOCOL) {
        return Err("UK ALPN protocol was not negotiated".into());
    }
    Ok(stream)
}

async fn connect_tls_carrier_after_probe(
    harness: &ServerHarness,
) -> Result<ClientTlsStream<TcpStream>, TestError> {
    let mut last_error = None;
    for _ in 0..20 {
        match connect_tls_carrier(harness).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_error = Some(err);
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| "failed to connect tls carrier".into()))
}

fn client_exporter(stream: &ClientTlsStream<TcpStream>) -> Result<[u8; 32], TestError> {
    let mut out = [0_u8; 32];
    stream
        .get_ref()
        .1
        .export_keying_material(&mut out, EXPORTER_LABEL, None)?;
    Ok(out)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TestError> {
    let pem = fs::read(path)?;
    let certs = CertificateDer::pem_slice_iter(&pem).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        Err("missing certificate".into())
    } else {
        Ok(certs)
    }
}

impl Drop for ServerHarness {
    fn drop(&mut self) {
        self.server_task.abort();
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

struct MalformedFrameServerHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    server_task: Option<JoinHandle<Result<ErrorCode, TestError>>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

#[derive(Clone, Copy)]
enum MalformedFrameScenario {
    RelayFrameAfterOpen,
    WrongProtocolFrameAfterOpen,
    NonEmptyOpenAck,
    OversizedFrameDuringOpen,
}

impl MalformedFrameServerHarness {
    async fn start() -> Result<Self, TestError> {
        Self::start_with_scenario(MalformedFrameScenario::RelayFrameAfterOpen).await
    }

    async fn start_wrong_protocol_frame() -> Result<Self, TestError> {
        Self::start_with_scenario(MalformedFrameScenario::WrongProtocolFrameAfterOpen).await
    }

    async fn start_non_empty_open_ack() -> Result<Self, TestError> {
        Self::start_with_scenario(MalformedFrameScenario::NonEmptyOpenAck).await
    }

    async fn start_oversized_frame_during_open() -> Result<Self, TestError> {
        Self::start_with_scenario(MalformedFrameScenario::OversizedFrameDuringOpen).await
    }

    async fn start_with_scenario(scenario: MalformedFrameScenario) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let server_task = tokio::spawn(run_malformed_frame_server(
            server_listener,
            cert_path.clone(),
            key_path,
            scenario,
        ));
        let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        })
        .await?;

        Ok(Self {
            temp_dir,
            socks_addr,
            server_task: Some(server_task),
            client_task,
        })
    }

    async fn received_error_code(&mut self) -> Result<ErrorCode, TestError> {
        let task = self
            .server_task
            .take()
            .ok_or("malformed frame server task was already awaited")?;
        tokio::time::timeout(Duration::from_secs(3), task).await??
    }
}

impl Drop for MalformedFrameServerHarness {
    fn drop(&mut self) {
        self.client_task.abort();
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

struct ClientBufferedLimitServerHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    server_task: Option<JoinHandle<Result<u16, TestError>>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

impl ClientBufferedLimitServerHarness {
    async fn start() -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let server_task = tokio::spawn(run_client_buffered_limit_server(
            server_listener,
            cert_path.clone(),
            key_path,
        ));
        let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: Some(1),
            max_carrier_sessions: None,
        })
        .await?;

        Ok(Self {
            temp_dir,
            socks_addr,
            server_task: Some(server_task),
            client_task,
        })
    }

    async fn observed_close_code(&mut self) -> Result<u16, TestError> {
        let task = self
            .server_task
            .take()
            .ok_or("client buffered limit server task was already awaited")?;
        tokio::time::timeout(Duration::from_secs(3), task).await??
    }
}

impl Drop for ClientBufferedLimitServerHarness {
    fn drop(&mut self) {
        self.client_task.abort();
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

struct UdpStreamFallbackDisabledServerHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    server_task: Option<JoinHandle<Result<(), TestError>>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

#[derive(Clone, Copy)]
enum UdpFallbackSettingsScenario {
    DisabledSupport,
    ZeroFlowCapacity,
}

impl UdpStreamFallbackDisabledServerHarness {
    async fn start() -> Result<Self, TestError> {
        Self::start_with_scenario(UdpFallbackSettingsScenario::DisabledSupport).await
    }

    async fn start_zero_flow_capacity() -> Result<Self, TestError> {
        Self::start_with_scenario(UdpFallbackSettingsScenario::ZeroFlowCapacity).await
    }

    async fn start_with_scenario(scenario: UdpFallbackSettingsScenario) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let server_task = tokio::spawn(run_udp_stream_fallback_disabled_server(
            server_listener,
            cert_path.clone(),
            key_path,
            scenario,
        ));
        let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        })
        .await?;

        Ok(Self {
            temp_dir,
            socks_addr,
            server_task: Some(server_task),
            client_task,
        })
    }

    async fn observed_no_udp_open(&mut self) -> Result<(), TestError> {
        let task = self
            .server_task
            .take()
            .ok_or("udp stream fallback server task was already awaited")?;
        tokio::time::timeout(Duration::from_secs(3), task).await??
    }
}

impl Drop for UdpStreamFallbackDisabledServerHarness {
    fn drop(&mut self) {
        self.client_task.abort();
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

struct PendingOpenCancelServerHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    server_task: Option<JoinHandle<Result<u16, TestError>>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

struct AckGatedOpenServerHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    open_rx: Option<oneshot::Receiver<()>>,
    ack_tx: Option<oneshot::Sender<()>>,
    server_task: Option<JoinHandle<Result<u16, TestError>>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

impl AckGatedOpenServerHarness {
    async fn start() -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let (open_tx, open_rx) = oneshot::channel();
        let (ack_tx, ack_rx) = oneshot::channel();
        let server_task = tokio::spawn(run_ack_gated_open_server(
            server_listener,
            cert_path.clone(),
            key_path,
            open_tx,
            ack_rx,
        ));
        let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(30),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        })
        .await?;

        Ok(Self {
            temp_dir,
            socks_addr,
            open_rx: Some(open_rx),
            ack_tx: Some(ack_tx),
            server_task: Some(server_task),
            client_task,
        })
    }

    async fn observed_tcp_open(&mut self) -> Result<(), TestError> {
        let open_rx = self
            .open_rx
            .take()
            .ok_or("ack-gated open signal was already awaited")?;
        tokio::time::timeout(Duration::from_secs(3), open_rx).await??;
        Ok(())
    }

    fn release_open_ack(&mut self) -> Result<(), TestError> {
        let ack_tx = self
            .ack_tx
            .take()
            .ok_or("ack-gated open ack was already released")?;
        ack_tx
            .send(())
            .map_err(|()| "ack-gated server stopped before ack release".into())
    }

    async fn received_close_code(&mut self) -> Result<u16, TestError> {
        let task = self
            .server_task
            .take()
            .ok_or("ack-gated open server task was already awaited")?;
        tokio::time::timeout(Duration::from_secs(3), task).await??
    }
}

impl Drop for AckGatedOpenServerHarness {
    fn drop(&mut self) {
        self.client_task.abort();
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

impl PendingOpenCancelServerHarness {
    async fn start() -> Result<Self, TestError> {
        Self::start_with_tcp_open_timeout(30).await
    }

    async fn start_with_tcp_open_timeout(tcp_open_timeout_seconds: u64) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let server_task = tokio::spawn(run_pending_open_cancel_server(
            server_listener,
            cert_path.clone(),
            key_path,
        ));
        let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(tcp_open_timeout_seconds),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        })
        .await?;

        Ok(Self {
            temp_dir,
            socks_addr,
            server_task: Some(server_task),
            client_task,
        })
    }

    async fn received_close_code(&mut self) -> Result<u16, TestError> {
        let task = self
            .server_task
            .take()
            .ok_or("pending open cancel server task was already awaited")?;
        tokio::time::timeout(Duration::from_secs(3), task).await??
    }
}

impl Drop for PendingOpenCancelServerHarness {
    fn drop(&mut self) {
        self.client_task.abort();
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

struct PendingUdpOpenCancelServerHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    open_rx: Option<oneshot::Receiver<()>>,
    server_task: Option<JoinHandle<Result<u16, TestError>>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

impl PendingUdpOpenCancelServerHarness {
    async fn start() -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let (open_tx, open_rx) = oneshot::channel();
        let server_task = tokio::spawn(run_pending_udp_open_cancel_server(
            server_listener,
            cert_path.clone(),
            key_path,
            open_tx,
        ));
        let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(30),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        })
        .await?;

        Ok(Self {
            temp_dir,
            socks_addr,
            open_rx: Some(open_rx),
            server_task: Some(server_task),
            client_task,
        })
    }

    async fn observed_udp_open(&mut self) -> Result<(), TestError> {
        let open_rx = self
            .open_rx
            .take()
            .ok_or("pending udp open signal was already awaited")?;
        tokio::time::timeout(Duration::from_secs(3), open_rx).await??;
        Ok(())
    }

    async fn received_close_code(&mut self) -> Result<u16, TestError> {
        let task = self
            .server_task
            .take()
            .ok_or("pending udp open cancel server task was already awaited")?;
        tokio::time::timeout(Duration::from_secs(3), task).await??
    }
}

impl Drop for PendingUdpOpenCancelServerHarness {
    fn drop(&mut self) {
        self.client_task.abort();
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

struct MissingPongServerHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    server_task: Option<JoinHandle<Result<(), TestError>>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

#[derive(Clone, Copy)]
enum PongBehavior {
    Missing,
    Empty,
    WrongNonce,
}

impl MissingPongServerHarness {
    async fn start() -> Result<Self, TestError> {
        Self::start_with_behavior(PongBehavior::Missing).await
    }

    async fn start_with_empty_pong() -> Result<Self, TestError> {
        Self::start_with_behavior(PongBehavior::Empty).await
    }

    async fn start_with_wrong_nonce_pong() -> Result<Self, TestError> {
        Self::start_with_behavior(PongBehavior::WrongNonce).await
    }

    async fn start_with_behavior(pong_behavior: PongBehavior) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let server_task = tokio::spawn(run_missing_pong_server(
            server_listener,
            cert_path.clone(),
            key_path,
            pong_behavior,
        ));
        let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        })
        .await?;

        Ok(Self {
            temp_dir,
            socks_addr,
            server_task: Some(server_task),
            client_task,
        })
    }

    async fn observed_client_close_after_ping(&mut self) -> Result<(), TestError> {
        let task = self
            .server_task
            .take()
            .ok_or("missing pong server task was already awaited")?;
        tokio::time::timeout(Duration::from_secs(4), task).await??
    }
}

impl Drop for MissingPongServerHarness {
    fn drop(&mut self) {
        self.client_task.abort();
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

async fn run_malformed_frame_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    scenario: MalformedFrameScenario,
) -> Result<ErrorCode, TestError> {
    let mut stream = accept_fake_server_session(listener, cert_path, key_path).await?;
    let open_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    assert_eq!(open_frame.header.frame_type, FrameType::TcpOpen);
    let flow_id = open_frame.header.id;
    let mut open_payload = open_frame.payload;
    TcpOpen::decode(&mut open_payload)?;

    match scenario {
        MalformedFrameScenario::RelayFrameAfterOpen => {
            let ack = Frame::new(FrameType::TcpData, 0, flow_id, Bytes::new())?;
            write_frame(&mut stream, &ack).await?;

            let malformed_close = Frame::new(FrameType::TcpClose, 0, flow_id, Bytes::new())?;
            write_frame(&mut stream, &malformed_close).await?;
        }
        MalformedFrameScenario::WrongProtocolFrameAfterOpen => {
            let ack = Frame::new(FrameType::TcpData, 0, flow_id, Bytes::new())?;
            write_frame(&mut stream, &ack).await?;

            let wrong_protocol = Frame::new(
                FrameType::UdpData,
                0,
                flow_id,
                Bytes::from_static(b"wrong protocol"),
            )?;
            write_frame(&mut stream, &wrong_protocol).await?;
        }
        MalformedFrameScenario::NonEmptyOpenAck => {
            let malformed_ack = Frame::new(
                FrameType::TcpData,
                0,
                flow_id,
                Bytes::from_static(b"not an ack"),
            )?;
            write_frame(&mut stream, &malformed_ack).await?;
        }
        MalformedFrameScenario::OversizedFrameDuringOpen => {
            write_oversized_tcp_data_header(&mut stream, flow_id).await?;
        }
    }

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    let expected_error_id = match scenario {
        MalformedFrameScenario::WrongProtocolFrameAfterOpen => flow_id,
        MalformedFrameScenario::RelayFrameAfterOpen
        | MalformedFrameScenario::NonEmptyOpenAck
        | MalformedFrameScenario::OversizedFrameDuringOpen => 0,
    };
    assert_eq!(response.header.id, expected_error_id);
    let mut payload = response.payload;
    let code = ErrorPayload::decode(&mut payload)?.code;

    if matches!(
        scenario,
        MalformedFrameScenario::WrongProtocolFrameAfterOpen
    ) {
        let close = tokio::time::timeout(
            Duration::from_secs(3),
            read_frame(&mut stream, FrameLimits::default()),
        )
        .await??;
        assert_eq!(close.header.frame_type, FrameType::TcpClose);
        assert_eq!(close.header.id, flow_id);
        let mut payload = close.payload;
        assert_eq!(TcpClose::decode(&mut payload)?.close_code, TCP_CLOSE_ERROR);
    }

    Ok(code)
}

async fn run_client_buffered_limit_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<u16, TestError> {
    let mut stream = accept_fake_server_session(listener, cert_path, key_path).await?;
    let open_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    assert_eq!(open_frame.header.frame_type, FrameType::TcpOpen);
    let flow_id = open_frame.header.id;
    let mut open_payload = open_frame.payload;
    TcpOpen::decode(&mut open_payload)?;

    let ack = Frame::new(FrameType::TcpData, 0, flow_id, Bytes::new())?;
    write_frame(&mut stream, &ack).await?;
    let oversized = Frame::new(FrameType::TcpData, 0, flow_id, Bytes::from_static(b"xx"))?;
    write_frame(&mut stream, &oversized).await?;

    let resource_limit = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await??;
    assert_eq!(resource_limit.header.frame_type, FrameType::ResourceLimit);
    assert_eq!(resource_limit.header.id, flow_id);
    let mut resource_payload = resource_limit.payload;
    assert_eq!(
        ErrorPayload::decode(&mut resource_payload)?.code,
        ErrorCode::ResourceLimit
    );

    let close = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await??;
    assert_eq!(close.header.frame_type, FrameType::TcpClose);
    assert_eq!(close.header.id, flow_id);
    let mut close_payload = close.payload;
    Ok(TcpClose::decode(&mut close_payload)?.close_code)
}

async fn run_ack_gated_open_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    open_tx: oneshot::Sender<()>,
    ack_rx: oneshot::Receiver<()>,
) -> Result<u16, TestError> {
    let mut stream = accept_fake_server_session(listener, cert_path, key_path).await?;
    let open_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    assert_eq!(open_frame.header.frame_type, FrameType::TcpOpen);
    let flow_id = open_frame.header.id;
    let mut open_payload = open_frame.payload;
    TcpOpen::decode(&mut open_payload)?;
    let _ = open_tx.send(());

    tokio::time::timeout(Duration::from_secs(3), ack_rx).await??;
    let ack = Frame::new(FrameType::TcpData, 0, flow_id, Bytes::new())?;
    write_frame(&mut stream, &ack).await?;

    let close_frame = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await??;
    assert_eq!(close_frame.header.frame_type, FrameType::TcpClose);
    assert_eq!(close_frame.header.id, flow_id);
    let mut payload = close_frame.payload;
    Ok(TcpClose::decode(&mut payload)?.close_code)
}

async fn run_pending_open_cancel_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<u16, TestError> {
    run_pending_open_cancel_server_with_signal(listener, cert_path, key_path, None).await
}

async fn run_pending_open_cancel_server_with_signal(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    open_tx: Option<oneshot::Sender<()>>,
) -> Result<u16, TestError> {
    let mut stream = accept_fake_server_session(listener, cert_path, key_path).await?;
    let open_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    assert_eq!(open_frame.header.frame_type, FrameType::TcpOpen);
    let flow_id = open_frame.header.id;
    let mut open_payload = open_frame.payload;
    TcpOpen::decode(&mut open_payload)?;
    if let Some(open_tx) = open_tx {
        let _ = open_tx.send(());
    }

    let close_frame = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await??;
    assert_eq!(close_frame.header.frame_type, FrameType::TcpClose);
    assert_eq!(close_frame.header.id, flow_id);
    let mut payload = close_frame.payload;
    Ok(TcpClose::decode(&mut payload)?.close_code)
}

async fn run_pending_udp_open_cancel_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    open_tx: oneshot::Sender<()>,
) -> Result<u16, TestError> {
    let mut stream = accept_fake_server_session(listener, cert_path, key_path).await?;
    let open_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    assert_eq!(open_frame.header.frame_type, FrameType::UdpOpen);
    let flow_id = open_frame.header.id;
    let mut open_payload = open_frame.payload;
    UdpOpen::decode(&mut open_payload)?;
    let _ = open_tx.send(());

    let close_frame = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await??;
    assert_eq!(close_frame.header.frame_type, FrameType::UdpClose);
    assert_eq!(close_frame.header.id, flow_id);
    let mut payload = close_frame.payload;
    Ok(UdpClose::decode(&mut payload)?.close_code)
}

async fn run_udp_stream_fallback_disabled_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    scenario: UdpFallbackSettingsScenario,
) -> Result<(), TestError> {
    let mut settings = fake_server_settings();
    match scenario {
        UdpFallbackSettingsScenario::DisabledSupport => {
            settings.set(SettingKey::SupportsUdpStreamFallback, 0);
        }
        UdpFallbackSettingsScenario::ZeroFlowCapacity => {
            settings.set(SettingKey::MaxUdpFlows, 0);
            settings.set(SettingKey::SupportsUdpStreamFallback, 1);
        }
    }
    let mut stream =
        accept_fake_server_session_with_settings(listener, cert_path, key_path, settings).await?;

    match tokio::time::timeout(
        Duration::from_millis(500),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await
    {
        Err(_) | Ok(Err(FrameIoError::Closed)) => Ok(()),
        Ok(Err(err)) => Err(err.into()),
        Ok(Ok(frame)) => Err(format!(
            "unexpected frame after disabled UDP stream fallback: {:?}",
            frame.header.frame_type
        )
        .into()),
    }
}

async fn run_missing_pong_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    pong_behavior: PongBehavior,
) -> Result<(), TestError> {
    let mut settings = fake_server_settings();
    settings.set(SettingKey::IdleTimeoutSeconds, 1);
    let mut stream =
        accept_fake_server_session_with_settings(listener, cert_path, key_path, settings).await?;
    let open_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    assert_eq!(open_frame.header.frame_type, FrameType::TcpOpen);
    let flow_id = open_frame.header.id;
    let mut open_payload = open_frame.payload;
    TcpOpen::decode(&mut open_payload)?;

    let ack = Frame::new(FrameType::TcpData, 0, flow_id, Bytes::new())?;
    write_frame(&mut stream, &ack).await?;

    let ping = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await??;
    validate_connection_frame(&ping, FrameType::Ping)?;

    match pong_behavior {
        PongBehavior::Missing => {}
        PongBehavior::Empty => {
            let empty_pong_frame = Frame::new(FrameType::Pong, 0, 0, Bytes::new())?;
            write_frame(&mut stream, &empty_pong_frame).await?;
        }
        PongBehavior::WrongNonce => {
            let ping_nonce = u64::from_be_bytes(ping.payload.as_ref().try_into()?);
            let wrong_nonce = ping_nonce
                .checked_add(1)
                .ok_or("test ping nonce overflow")?;
            let wrong_pong = Frame::new(
                FrameType::Pong,
                0,
                0,
                Bytes::copy_from_slice(&wrong_nonce.to_be_bytes()),
            )?;
            write_frame(&mut stream, &wrong_pong).await?;
        }
    }

    match tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut stream, FrameLimits::default()),
    )
    .await
    {
        Ok(Err(FrameIoError::Closed)) => Ok(()),
        Ok(Ok(frame)) => Err(format!(
            "unexpected frame after unanswered ping: {:?}",
            frame.header.frame_type
        )
        .into()),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Err("client did not close session after unanswered ping".into()),
    }
}

async fn run_udp_reconnect_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    first_closed_tx: oneshot::Sender<()>,
) -> Result<(), TestError> {
    let mut first = accept_fake_server_session_from_listener(
        &listener,
        &cert_path,
        &key_path,
        fake_server_settings(),
    )
    .await?;
    let (first_flow_id, first_target) = accept_fake_udp_flow(&mut first).await?;
    let first_data = read_fake_udp_data(&mut first, first_flow_id).await?;
    assert_eq!(first_data, Bytes::from_static(b"first carrier"));
    drop(first);
    let _ = first_closed_tx.send(());

    let mut second = accept_fake_server_session_from_listener(
        &listener,
        &cert_path,
        &key_path,
        fake_server_settings(),
    )
    .await?;
    let (second_flow_id, second_target) = accept_fake_udp_flow(&mut second).await?;
    assert_eq!(second_target, first_target);
    let second_data = read_fake_udp_data(&mut second, second_flow_id).await?;
    assert_eq!(second_data, Bytes::from_static(b"recovered carrier"));
    let reply = Frame::new(FrameType::UdpData, 0, second_flow_id, second_data)?;
    write_frame(&mut second, &reply).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}

async fn accept_fake_udp_flow(
    stream: &mut ServerTlsStream<TcpStream>,
) -> Result<(u64, Target), TestError> {
    let open = read_frame(stream, FrameLimits::default()).await?;
    assert_eq!(open.header.frame_type, FrameType::UdpOpen);
    let flow_id = open.header.id;
    let mut payload = open.payload;
    let target = UdpOpen::decode(&mut payload)?.target;
    let ack = Frame::new(FrameType::UdpData, 0, flow_id, Bytes::new())?;
    write_frame(stream, &ack).await?;
    Ok((flow_id, target))
}

async fn read_fake_udp_data(
    stream: &mut ServerTlsStream<TcpStream>,
    flow_id: u64,
) -> Result<Bytes, TestError> {
    loop {
        let frame = read_frame(stream, FrameLimits::default()).await?;
        match frame.header.frame_type {
            FrameType::UdpData if frame.header.id == flow_id => return Ok(frame.payload),
            FrameType::Ping => {
                let pong = Frame::new(FrameType::Pong, 0, 0, frame.payload)?;
                write_frame(stream, &pong).await?;
            }
            other => {
                return Err(
                    format!("unexpected frame while waiting for UDP data: {other:?}").into(),
                );
            }
        }
    }
}

async fn accept_fake_server_session(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<ServerTlsStream<TcpStream>, TestError> {
    accept_fake_server_session_with_settings(listener, cert_path, key_path, fake_server_settings())
        .await
}

async fn accept_fake_server_session_with_settings(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    settings: Settings,
) -> Result<ServerTlsStream<TcpStream>, TestError> {
    accept_fake_server_session_from_listener(&listener, &cert_path, &key_path, settings).await
}

async fn accept_fake_server_session_from_listener(
    listener: &TcpListener,
    cert_path: &Path,
    key_path: &Path,
    settings: Settings,
) -> Result<ServerTlsStream<TcpStream>, TestError> {
    let (tcp, _) = listener.accept().await?;
    tcp.set_nodelay(true)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(cert_path, key_path)?));
    let mut stream = acceptor.accept(tcp).await?;
    if stream.get_ref().1.alpn_protocol() != Some(ALPN_PROTOCOL) {
        return Err("UK ALPN protocol was not negotiated".into());
    }

    let exporter = server_exporter(&stream)?;
    let challenge = AuthChallenge::generate(unix_now());
    let mut challenge_payload = BytesMut::new();
    challenge.encode(&mut challenge_payload)?;
    let challenge_frame = Frame::new(FrameType::AuthChallenge, 0, 0, challenge_payload.freeze())?;
    write_frame(&mut stream, &challenge_frame).await?;

    let response_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    validate_connection_frame(&response_frame, FrameType::AuthResponse)?;
    let mut response_payload = response_frame.payload;
    let response = AuthResponse::decode(&mut response_payload)?;
    let credentials = [Credential::active(
        KEY_ID.as_bytes().to_vec(),
        SECRET.as_bytes().to_vec(),
    )?];
    let mut replay_cache = ReplayCache::default();
    verify_auth_response(
        &credentials,
        &exporter,
        &challenge,
        &response,
        unix_now(),
        Duration::from_secs(30),
        &mut replay_cache,
    )?;

    let mut settings_payload = BytesMut::new();
    settings.encode(&mut settings_payload)?;
    let settings_frame = Frame::new(FrameType::Settings, 0, 0, settings_payload.freeze())?;
    write_frame(&mut stream, &settings_frame).await?;
    Ok(stream)
}

fn server_tls_config(cert_path: &Path, key_path: &Path) -> Result<RustlsServerConfig, TestError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut config = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    config.max_early_data_size = 0;
    Ok(config)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TestError> {
    let pem = fs::read(path)?;
    Ok(PrivateKeyDer::from_pem_slice(&pem)?)
}

fn server_exporter(stream: &ServerTlsStream<TcpStream>) -> Result<[u8; 32], TestError> {
    let mut out = [0_u8; 32];
    stream
        .get_ref()
        .1
        .export_keying_material(&mut out, EXPORTER_LABEL, None)?;
    Ok(out)
}

fn fake_server_settings() -> Settings {
    let mut settings = Settings::default();
    settings.set(SettingKey::ProtocolRevision, 1);
    settings.set(SettingKey::MaxFrameSize, 65_536);
    settings.set(SettingKey::MaxStreams, 8);
    settings.set(SettingKey::MaxUdpFlows, 8);
    settings.set(SettingKey::SupportsUdpDatagram, 0);
    settings.set(SettingKey::SupportsUdpStreamFallback, 1);
    settings.set(SettingKey::IdleTimeoutSeconds, 30);
    settings
}

struct RelayHarness {
    temp_dir: PathBuf,
    socks_addr: SocketAddr,
    server_task: JoinHandle<Result<(), TestError>>,
    client_task: JoinHandle<Result<(), TestError>>,
}

struct ReloadableSocksListener {
    socks_addr: SocketAddr,
    reload_handle: ClientReloadHandle,
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<Result<(), TestError>>,
}

struct UdpReloadProbe {
    _control: TcpStream,
    client: UdpSocket,
    relay_addr: SocketAddr,
    old_target_addr: SocketAddr,
    old_target_task: Option<JoinHandle<Result<(), TestError>>>,
}

impl UdpReloadProbe {
    async fn start(socks_addr: SocketAddr) -> Result<Self, TestError> {
        let (old_target_addr, old_target_task) = spawn_udp_echo_target_roundtrips(2).await?;
        let (control, relay_addr) = open_socks_udp_associate(socks_addr).await?;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        assert_socks_udp_roundtrip(
            &client,
            relay_addr,
            old_target_addr,
            b"old UDP flow before client reload",
        )
        .await?;
        Ok(Self {
            _control: control,
            client,
            relay_addr,
            old_target_addr,
            old_target_task: Some(old_target_task),
        })
    }

    async fn verify_after_reload(&mut self) -> Result<(), TestError> {
        let (new_target_addr, new_target_task) = spawn_udp_echo_target().await?;
        assert_socks_udp_roundtrip(
            &self.client,
            self.relay_addr,
            new_target_addr,
            b"new UDP flow after client reload",
        )
        .await?;
        assert_socks_udp_roundtrip(
            &self.client,
            self.relay_addr,
            self.old_target_addr,
            b"old UDP flow survives client reload",
        )
        .await?;
        new_target_task.await??;
        self.old_target_task
            .take()
            .ok_or("missing old UDP target task")?
            .await??;
        Ok(())
    }
}

impl RelayHarness {
    async fn start(policy_toml: Option<String>) -> Result<Self, TestError> {
        Self::start_with_limits(policy_toml, test_limits()).await
    }

    async fn start_with_max_socks_connections(
        policy_toml: Option<String>,
        max_socks_connections: u64,
    ) -> Result<Self, TestError> {
        Self::start_with_client_options(
            policy_toml,
            test_limits(),
            3,
            Some(max_socks_connections),
            None,
            None,
        )
        .await
    }

    async fn start_with_client_socks_timeout(
        policy_toml: Option<String>,
        socks_handshake_timeout_seconds: u64,
    ) -> Result<Self, TestError> {
        Self::start_with_client_options(
            policy_toml,
            test_limits(),
            socks_handshake_timeout_seconds,
            None,
            None,
            None,
        )
        .await
    }

    async fn start_with_limits(
        policy_toml: Option<String>,
        limits: LimitConfig,
    ) -> Result<Self, TestError> {
        Self::start_with_client_options(policy_toml, limits, 3, None, None, None).await
    }

    async fn start_with_limits_and_pool(
        policy_toml: Option<String>,
        limits: LimitConfig,
        max_carrier_sessions: u64,
    ) -> Result<Self, TestError> {
        Self::start_with_client_options(
            policy_toml,
            limits,
            3,
            None,
            None,
            Some(max_carrier_sessions),
        )
        .await
    }

    async fn start_with_client_udp_idle_timeout(
        policy_toml: Option<String>,
        limits: LimitConfig,
        udp_flow_idle_timeout_seconds: u64,
    ) -> Result<Self, TestError> {
        Self::start_with_client_options(
            policy_toml,
            limits,
            3,
            None,
            Some(udp_flow_idle_timeout_seconds),
            None,
        )
        .await
    }

    async fn start_with_client_options(
        policy_toml: Option<String>,
        limits: LimitConfig,
        socks_handshake_timeout_seconds: u64,
        max_socks_connections: Option<u64>,
        udp_flow_idle_timeout_seconds: Option<u64>,
        max_carrier_sessions: Option<u64>,
    ) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        write_private_key(&key_path)?;

        let policy_path = if let Some(policy_toml) = policy_toml {
            let policy_path = temp_dir.join("policy.toml");
            fs::write(&policy_path, policy_toml)?;
            Some(policy_path)
        } else {
            None
        };

        let (server_addr, server_task) = start_uk_server(test_server_config(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &cert_path,
            &key_path,
            limits,
            policy_path.as_deref(),
            30,
        ))
        .await?;

        let (socks_addr, client_task) = start_socks5_listener(ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: Some(socks_handshake_timeout_seconds),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions,
        })
        .await?;

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

async fn spawn_udp_echo_target()
-> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    spawn_udp_echo_target_roundtrips(1).await
}

async fn spawn_udp_echo_target_roundtrips(
    roundtrips: usize,
) -> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0_u8; 1024];
        for _ in 0..roundtrips {
            let (read, peer) = socket.recv_from(&mut buf).await?;
            socket.send_to(&buf[..read], peer).await?;
        }
        Ok(())
    });
    Ok((addr, task))
}

async fn spawn_udp_oversized_then_echo_target(
    oversized_len: usize,
) -> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0_u8; 1024];
        let (_read, peer) = socket.recv_from(&mut buf).await?;
        let oversized = vec![0x5a; oversized_len];
        socket.send_to(&oversized, peer).await?;

        let (read, peer) = socket.recv_from(&mut buf).await?;
        socket.send_to(&buf[..read], peer).await?;
        Ok(())
    });
    Ok((addr, task))
}

async fn spawn_udp_downstream_activity_target()
-> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0_u8; 1024];
        let (_read, peer) = socket.recv_from(&mut buf).await?;
        for payload in [
            b"downstream-0".as_slice(),
            b"downstream-1".as_slice(),
            b"downstream-2".as_slice(),
            b"downstream-3".as_slice(),
        ] {
            socket.send_to(payload, peer).await?;
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
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

async fn spawn_two_stage_echo_target(
    first_len: usize,
    second_len: usize,
) -> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut first = vec![0_u8; first_len];
        stream.read_exact(&mut first).await?;
        stream.write_all(&first).await?;

        let mut second = vec![0_u8; second_len];
        stream.read_exact(&mut second).await?;
        stream.write_all(&second).await?;
        Ok(())
    });
    Ok((addr, task))
}

async fn spawn_barrier_echo_target(
    expected_len: usize,
    barrier: Arc<Barrier>,
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
        let mut received = vec![0_u8; expected_len];
        stream.read_exact(&mut received).await?;
        barrier.wait().await;
        stream.write_all(&received).await?;
        Ok(received)
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

async fn spawn_read_to_eof_until_released_target() -> Result<
    (
        SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<Vec<u8>, TestError>>,
    ),
    TestError,
> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (release_tx, release_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        let _ = release_rx.await;
        Ok(received)
    });
    Ok((addr, release_tx, task))
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

async fn spawn_ipv6_echo_target()
-> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
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

async fn http_get(addr: SocketAddr, path: &str) -> Result<String, TestError> {
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

async fn wait_for_server_metric(addr: SocketAddr, expected: &str) -> Result<(), TestError> {
    for _ in 0..100 {
        if http_get(addr, "/metrics")
            .await
            .is_ok_and(|metrics| metrics.contains(expected))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("server metric did not reach `{}`", expected.trim()).into())
}

async fn wait_for_client_metric(addr: SocketAddr, expected: &str) -> Result<(), TestError> {
    wait_for_server_metric(addr, expected).await
}

async fn wait_for_active_server_sessions(
    addr: SocketAddr,
    expected: usize,
) -> Result<(), TestError> {
    wait_for_server_metric(
        addr,
        &format!("uncrowned_king_server_active_sessions {expected}\n"),
    )
    .await
}

fn test_server_config(
    listen: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    limits: LimitConfig,
    policy_path: Option<&Path>,
    auth_skew_seconds: u64,
) -> ServerConfig {
    ServerConfig {
        listen: listen.to_string(),
        quic_listen: None,
        observability_listen: None,
        cert_path: path_string(cert_path),
        key_path: path_string(key_path),
        auth_skew_seconds: Some(auth_skew_seconds),
        limits: Some(limits),
        policy_path: policy_path.map(path_string),
        credentials: vec![CredentialConfig {
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            status: Some("active".to_owned()),
            not_before: None,
            not_after: None,
            policy_group: Some("default".to_owned()),
        }],
    }
}

fn quic_test_client_config(quic_addr: SocketAddr, cert_path: &Path, secret: &str) -> ClientConfig {
    let mut config = test_client_config(quic_addr, cert_path, secret);
    config.server_addr = format!("quic://{quic_addr}");
    config
}

fn test_client_config(server_addr: SocketAddr, cert_path: &Path, secret: &str) -> ClientConfig {
    ClientConfig {
        server_addr: server_addr.to_string(),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        observability_listen: None,
        ca_cert_path: path_string(cert_path),
        key_id: KEY_ID.to_owned(),
        secret: secret.to_owned(),
        handshake_timeout_seconds: Some(3),
        server_connect_retry_delay_millis: None,
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: Some(3),
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
        max_carrier_sessions: None,
    }
}

async fn start_uk_server(
    config: ServerConfig,
) -> Result<(SocketAddr, JoinHandle<Result<(), TestError>>), TestError> {
    start_uk_server_until_shutdown(config, std::future::pending()).await
}

async fn start_uk_server_until_shutdown<F>(
    config: ServerConfig,
    shutdown: F,
) -> Result<(SocketAddr, JoinHandle<Result<(), TestError>>), TestError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_addr = listener.local_addr()?;
    let server_task =
        start_uk_server_on_listener_until_shutdown(config, listener, shutdown).await?;
    Ok((server_addr, server_task))
}

async fn start_uk_server_on_listener_until_shutdown<F>(
    config: ServerConfig,
    listener: TcpListener,
    shutdown: F,
) -> Result<JoinHandle<Result<(), TestError>>, TestError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let server_addr = listener.local_addr()?;
    let mut server_task = tokio::spawn(uk_server::run_on_listener_until_shutdown(
        config, listener, shutdown,
    ));
    wait_for_listener("uk-server", server_addr, &mut server_task).await?;
    Ok(server_task)
}

async fn start_socks5_listener(
    config: ClientConfig,
) -> Result<(SocketAddr, JoinHandle<Result<(), TestError>>), TestError> {
    start_socks5_listener_until_shutdown(config, std::future::pending()).await
}

async fn start_socks5_listener_until_shutdown<F>(
    config: ClientConfig,
    shutdown: F,
) -> Result<(SocketAddr, JoinHandle<Result<(), TestError>>), TestError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    uk_client::check_config(&config)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let socks_addr = listener.local_addr()?;
    let mut client_task = tokio::spawn(run_socks5_listener_on_until_shutdown(
        config, listener, shutdown,
    ));
    wait_for_listener("uk-client", socks_addr, &mut client_task).await?;
    Ok((socks_addr, client_task))
}

async fn start_reloadable_socks5_listener(
    config: ClientConfig,
) -> Result<ReloadableSocksListener, TestError> {
    uk_client::check_config(&config)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let socks_addr = listener.local_addr()?;
    let (reload_handle, reload_rx) = client_reload_channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut task = tokio::spawn(run_socks5_listener_on_until_shutdown_with_reload(
        config,
        listener,
        reload_rx,
        async {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-client", socks_addr, &mut task).await?;
    Ok(ReloadableSocksListener {
        socks_addr,
        reload_handle,
        shutdown_tx,
        task,
    })
}

async fn open_socks_connect(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
) -> Result<(TcpStream, [u8; 10]), TestError> {
    let request = socks_connect_request(target_addr);

    let mut socks = TcpStream::connect(socks_addr).await?;
    socks.write_all(&request).await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);
    let mut connect_reply = [0_u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    Ok((socks, connect_reply))
}

async fn open_socks_udp_associate(
    socks_addr: SocketAddr,
) -> Result<(TcpStream, SocketAddr), TestError> {
    let (mut socks, head) = open_socks_udp_associate_reply(socks_addr).await?;
    assert_eq!(head[1], SOCKS_REPLY_SUCCEEDED);
    let bound_addr = read_socks_reply_addr(&mut socks, head[3]).await?;
    Ok((socks, bound_addr))
}

async fn open_socks_udp_associate_from(
    socks_addr: SocketAddr,
    client_endpoint: SocketAddr,
) -> Result<(TcpStream, SocketAddr), TestError> {
    let (mut socks, head) =
        open_socks_udp_associate_reply_from(socks_addr, client_endpoint).await?;
    assert_eq!(head[1], SOCKS_REPLY_SUCCEEDED);
    let bound_addr = read_socks_reply_addr(&mut socks, head[3]).await?;
    Ok((socks, bound_addr))
}

async fn open_socks_udp_associate_reply(
    socks_addr: SocketAddr,
) -> Result<(TcpStream, [u8; 4]), TestError> {
    open_socks_udp_associate_reply_from(socks_addr, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await
}

async fn open_socks_udp_associate_reply_from(
    socks_addr: SocketAddr,
    client_endpoint: SocketAddr,
) -> Result<(TcpStream, [u8; 4]), TestError> {
    let mut socks = TcpStream::connect(socks_addr).await?;
    socks
        .write_all(&socks_udp_associate_request(client_endpoint))
        .await?;

    let mut method_response = [0_u8; 2];
    socks.read_exact(&mut method_response).await?;
    assert_eq!(method_response, [0x05, 0x00]);

    let mut head = [0_u8; 4];
    socks.read_exact(&mut head).await?;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[2], 0x00);
    Ok((socks, head))
}

fn socks_udp_associate_request(client_endpoint: SocketAddr) -> Vec<u8> {
    let port = client_endpoint.port();
    let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x03, 0x00];
    match client_endpoint {
        SocketAddr::V4(addr) => {
            request.push(0x01);
            request.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            request.push(0x04);
            request.extend_from_slice(&addr.ip().octets());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    request
}

async fn read_socks_reply_addr(
    socks: &mut TcpStream,
    addr_type: u8,
) -> Result<SocketAddr, TestError> {
    match addr_type {
        0x01 => {
            let mut octets = [0_u8; 4];
            socks.read_exact(&mut octets).await?;
            let port = read_socks_port(socks).await?;
            Ok(SocketAddr::from((Ipv4Addr::from(octets), port)))
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            socks.read_exact(&mut octets).await?;
            let port = read_socks_port(socks).await?;
            Ok(SocketAddr::from((Ipv6Addr::from(octets), port)))
        }
        other => Err(format!("unexpected socks reply address type: {other:#x}").into()),
    }
}

async fn read_socks_port(socks: &mut TcpStream) -> Result<u16, TestError> {
    let mut port = [0_u8; 2];
    socks.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

fn tcp_open_frame(flow_id: u64, target_addr: SocketAddr) -> Result<Frame, TestError> {
    let open = TcpOpen::new(target_from_socket_addr(target_addr), TCP_OPEN_FLAGS_NONE);
    let mut payload = BytesMut::new();
    open.encode(&mut payload)?;
    Ok(Frame::new(
        FrameType::TcpOpen,
        0,
        flow_id,
        payload.freeze(),
    )?)
}

fn malformed_tcp_open_flags_frame(
    flow_id: u64,
    target_addr: SocketAddr,
) -> Result<Frame, TestError> {
    let mut payload = BytesMut::new();
    target_from_socket_addr(target_addr).encode(&mut payload)?;
    payload.extend_from_slice(&1_u16.to_be_bytes());
    Ok(Frame::new(
        FrameType::TcpOpen,
        0,
        flow_id,
        payload.freeze(),
    )?)
}

fn udp_open_frame(flow_id: u64, target_addr: SocketAddr) -> Result<Frame, TestError> {
    let open = UdpOpen::new(target_from_socket_addr(target_addr));
    let mut payload = BytesMut::new();
    open.encode(&mut payload)?;
    Ok(Frame::new(
        FrameType::UdpOpen,
        0,
        flow_id,
        payload.freeze(),
    )?)
}

fn malformed_udp_open_target_frame(flow_id: u64) -> Result<Frame, TestError> {
    Ok(Frame::new(
        FrameType::UdpOpen,
        0,
        flow_id,
        Bytes::from_static(&[0xff, 0x00, 0x00, 0x35]),
    )?)
}

fn tcp_close_frame(flow_id: u64, close_code: u16) -> Result<Frame, TestError> {
    let mut payload = BytesMut::new();
    TcpClose::new(close_code).encode(&mut payload)?;
    Ok(Frame::new(
        FrameType::TcpClose,
        0,
        flow_id,
        payload.freeze(),
    )?)
}

fn udp_close_frame(flow_id: u64, close_code: u16) -> Result<Frame, TestError> {
    let mut payload = BytesMut::new();
    UdpClose::new(close_code).encode(&mut payload)?;
    Ok(Frame::new(
        FrameType::UdpClose,
        0,
        flow_id,
        payload.freeze(),
    )?)
}

fn flow_status_frame(
    frame_type: FrameType,
    flow_id: u64,
    code: ErrorCode,
) -> Result<Frame, TestError> {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload)?;
    Ok(Frame::new(frame_type, 0, flow_id, payload.freeze())?)
}

async fn write_oversized_tcp_data_header<W>(writer: &mut W, flow_id: u64) -> Result<(), TestError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    write_oversized_frame_header(
        writer,
        FrameType::TcpData,
        flow_id,
        FrameLimits::default().max_frame_size,
    )
    .await
}

async fn write_oversized_frame_header<W>(
    writer: &mut W,
    frame_type: FrameType,
    id: u64,
    limit: u64,
) -> Result<(), TestError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let header = FrameHeader::new(frame_type, 0, id, limit + 1)?;
    let mut encoded = BytesMut::new();
    header.encode(&mut encoded)?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_open_ack<C: AsyncRead + AsyncWrite + Unpin>(
    carrier: &mut C,
    flow_id: u64,
) -> Result<(), TestError> {
    let frame = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(frame.header.frame_type, FrameType::TcpData);
    assert_eq!(frame.header.id, flow_id);
    assert!(frame.payload.is_empty());
    Ok(())
}

async fn read_udp_open_ack<C: AsyncRead + AsyncWrite + Unpin>(
    carrier: &mut C,
    flow_id: u64,
) -> Result<(), TestError> {
    let frame = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(frame.header.frame_type, FrameType::UdpData);
    assert_eq!(frame.header.id, flow_id);
    assert!(frame.payload.is_empty());
    Ok(())
}

async fn read_relay_frame<C: AsyncRead + AsyncWrite + Unpin>(
    carrier: &mut C,
    frame_type: FrameType,
    flow_id: u64,
) -> Result<Frame, TestError> {
    for _ in 0..8 {
        let frame = tokio::time::timeout(
            Duration::from_secs(3),
            read_frame(carrier, FrameLimits::default()),
        )
        .await??;
        if frame.header.frame_type == frame_type && frame.header.id == flow_id {
            return Ok(frame);
        }
    }
    Err(format!("did not receive {frame_type:?} for flow {flow_id}").into())
}

async fn assert_flow_error<C: AsyncRead + AsyncWrite + Unpin>(
    carrier: &mut C,
    flow_id: u64,
    expected: ErrorCode,
) -> Result<(), TestError> {
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Error);
    assert_eq!(response.header.id, flow_id);
    let mut payload = response.payload;
    assert_eq!(ErrorPayload::decode(&mut payload)?.code, expected);
    Ok(())
}

async fn assert_tcp_close<C: AsyncRead + AsyncWrite + Unpin>(
    carrier: &mut C,
    flow_id: u64,
    expected: u16,
) -> Result<(), TestError> {
    let close = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(close.header.frame_type, FrameType::TcpClose);
    assert_eq!(close.header.id, flow_id);
    let mut payload = close.payload;
    assert_eq!(TcpClose::decode(&mut payload)?.close_code, expected);
    Ok(())
}

async fn assert_udp_close<C: AsyncRead + AsyncWrite + Unpin>(
    carrier: &mut C,
    flow_id: u64,
    expected: u16,
) -> Result<(), TestError> {
    let close = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(close.header.frame_type, FrameType::UdpClose);
    assert_eq!(close.header.id, flow_id);
    let mut payload = close.payload;
    assert_eq!(UdpClose::decode(&mut payload)?.close_code, expected);
    Ok(())
}

async fn write_ping_expect_pong<C: AsyncRead + AsyncWrite + Unpin>(
    carrier: &mut C,
    payload: Bytes,
) -> Result<(), TestError> {
    let frame = Frame::new(FrameType::Ping, 0, 0, payload.clone())?;
    write_frame(carrier, &frame).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(response.header.frame_type, FrameType::Pong);
    assert_eq!(response.header.id, 0);
    assert_eq!(response.payload, payload);
    Ok(())
}

fn target_from_socket_addr(target_addr: SocketAddr) -> Target {
    match target_addr {
        SocketAddr::V4(addr) => Target::Ipv4(*addr.ip(), addr.port()),
        SocketAddr::V6(addr) => Target::Ipv6(*addr.ip(), addr.port()),
    }
}

fn socks_connect_request(target_addr: SocketAddr) -> Vec<u8> {
    let port = target_addr.port();
    let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00];
    match target_addr {
        SocketAddr::V4(addr) => {
            request.push(0x01);
            request.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            request.push(0x04);
            request.extend_from_slice(&addr.ip().octets());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    request
}

fn reset_tcp_stream(stream: TcpStream) -> io::Result<()> {
    let stream = stream.into_std()?;
    let socket = Socket::from(stream);
    socket.set_linger(Some(Duration::ZERO))?;
    drop(socket);
    Ok(())
}

fn socks_udp_datagram(target_addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![0x00, 0x00, 0x00];
    match target_addr {
        SocketAddr::V4(addr) => {
            datagram.push(0x01);
            datagram.extend_from_slice(&addr.ip().octets());
            datagram.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            datagram.push(0x04);
            datagram.extend_from_slice(&addr.ip().octets());
            datagram.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    datagram.extend_from_slice(payload);
    datagram
}

fn parse_socks_udp_datagram(datagram: &[u8]) -> Result<(SocketAddr, Vec<u8>), TestError> {
    if datagram.len() < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0 {
        return Err("invalid socks udp datagram header".into());
    }
    match datagram[3] {
        0x01 => {
            if datagram.len() < 10 {
                return Err("truncated socks udp ipv4 datagram".into());
            }
            let addr = Ipv4Addr::new(datagram[4], datagram[5], datagram[6], datagram[7]);
            let port = u16::from_be_bytes([datagram[8], datagram[9]]);
            Ok((SocketAddr::from((addr, port)), datagram[10..].to_vec()))
        }
        0x04 => {
            if datagram.len() < 22 {
                return Err("truncated socks udp ipv6 datagram".into());
            }
            let octets: [u8; 16] = datagram[4..20].try_into()?;
            let port = u16::from_be_bytes([datagram[20], datagram[21]]);
            Ok((
                SocketAddr::from((Ipv6Addr::from(octets), port)),
                datagram[22..].to_vec(),
            ))
        }
        other => Err(format!("unexpected socks udp address type: {other:#x}").into()),
    }
}

async fn recv_socks_udp_datagram(
    udp_client: &UdpSocket,
    udp_relay_addr: SocketAddr,
) -> Result<(SocketAddr, Vec<u8>), TestError> {
    let mut buf = vec![0_u8; 1024];
    let (read, peer) =
        tokio::time::timeout(Duration::from_secs(3), udp_client.recv_from(&mut buf)).await??;
    assert_eq!(peer, udp_relay_addr);
    parse_socks_udp_datagram(&buf[..read])
}

async fn assert_socks_udp_roundtrip(
    client: &UdpSocket,
    relay_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) -> Result<(), TestError> {
    client
        .send_to(&socks_udp_datagram(target_addr, payload), relay_addr)
        .await?;
    let (reply_target, reply_payload) = recv_socks_udp_datagram(client, relay_addr).await?;
    assert_eq!(reply_target, target_addr);
    assert_eq!(reply_payload, payload);
    Ok(())
}

async fn assert_no_socks_udp_datagram(udp_client: &UdpSocket) -> Result<(), TestError> {
    let mut buf = [0_u8; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), udp_client.recv_from(&mut buf))
            .await
            .is_err(),
        "unexpected SOCKS UDP datagram"
    );
    Ok(())
}

async fn assert_echo_roundtrip(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) -> Result<(), TestError> {
    let (mut socks, connect_reply) = open_socks_connect(socks_addr, target_addr).await?;
    assert_eq!(connect_reply[1], SOCKS_REPLY_SUCCEEDED);

    socks.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, payload);
    Ok(())
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
    for _ in 0..TEST_LOOPBACK_PORT_SPAN {
        let sequence = NEXT_LOOPBACK_PORT_OFFSET.fetch_add(1, Ordering::Relaxed);
        let port = test_loopback_port(sequence);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if let Ok(listener) = TcpListener::bind(addr).await {
            drop(listener);
            return Ok(addr);
        }
    }
    Err("no available loopback port in test range".into())
}

async fn unused_udp_loopback_addr() -> Result<SocketAddr, TestError> {
    for _ in 0..TEST_LOOPBACK_PORT_SPAN {
        let sequence = NEXT_LOOPBACK_PORT_OFFSET.fetch_add(1, Ordering::Relaxed);
        let port = test_loopback_port(sequence);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if let Ok(socket) = UdpSocket::bind(addr).await {
            drop(socket);
            return Ok(addr);
        }
    }
    Err("no available loopback UDP port in test range".into())
}

fn test_loopback_port(sequence: u16) -> u16 {
    TEST_LOOPBACK_PORT_BASE
        + (test_loopback_start_offset().wrapping_add(sequence) % TEST_LOOPBACK_PORT_SPAN)
}

fn test_loopback_start_offset() -> u16 {
    *TEST_LOOPBACK_START_OFFSET.get_or_init(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or_default();
        let mut seed = u64::from(process::id()) ^ now.rotate_left(17);
        seed ^= seed >> 33;
        seed = seed.wrapping_mul(0xff51_afd7_ed55_8ccd);
        seed ^= seed >> 33;
        (seed % u64::from(TEST_LOOPBACK_PORT_SPAN)) as u16
    })
}

#[test]
fn test_loopback_candidate_ports_stay_in_test_range() {
    let upper_bound = TEST_LOOPBACK_PORT_BASE + TEST_LOOPBACK_PORT_SPAN;
    assert!(test_loopback_start_offset() < TEST_LOOPBACK_PORT_SPAN);

    for sequence in [
        0,
        1,
        TEST_LOOPBACK_PORT_SPAN - 1,
        TEST_LOOPBACK_PORT_SPAN,
        TEST_LOOPBACK_PORT_SPAN + 1,
    ] {
        let port = test_loopback_port(sequence);
        assert!((TEST_LOOPBACK_PORT_BASE..upper_bound).contains(&port));
    }
}

fn test_limits() -> LimitConfig {
    LimitConfig {
        max_pre_auth_bytes: Some(4096),
        max_frame_size: Some(65_536),
        max_sessions: Some(32),
        max_handshakes: Some(32),
        max_streams: Some(8),
        max_udp_flows: None,
        max_outbound_dials_per_session: Some(8),
        max_buffered_bytes_per_session: Some(4 * 1024 * 1024),
        idle_timeout_seconds: Some(30),
        max_buffered_bytes_per_flow: Some(1024 * 1024),
        handshake_timeout_seconds: Some(3),
        target_connect_timeout_seconds: Some(3),
        tcp_half_close_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        shutdown_timeout_seconds: None,
        replay_cache_window_seconds: None,
        replay_cache_max_entries: None,
    }
}

fn test_limits_with_max_streams(max_streams: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.max_streams = Some(max_streams);
    limits
}

fn test_limits_with_max_udp_flows(max_udp_flows: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.max_udp_flows = Some(max_udp_flows);
    limits
}

fn test_limits_with_udp_idle_timeout(udp_flow_idle_timeout_seconds: u64) -> LimitConfig {
    let mut limits = test_limits_with_max_udp_flows(1);
    limits.udp_flow_idle_timeout_seconds = Some(udp_flow_idle_timeout_seconds);
    limits
}

fn test_limits_with_max_sessions(max_sessions: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.max_sessions = Some(max_sessions);
    limits
}

fn test_limits_with_max_handshakes(max_handshakes: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.max_handshakes = Some(max_handshakes);
    limits
}

fn test_limits_with_max_frame_size(max_frame_size: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.max_frame_size = Some(max_frame_size);
    limits
}

fn test_limits_with_idle_timeout(idle_timeout_seconds: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.idle_timeout_seconds = Some(idle_timeout_seconds);
    limits
}

fn test_limits_with_buffered_bytes_per_flow(max_buffered_bytes_per_flow: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.max_buffered_bytes_per_flow = Some(max_buffered_bytes_per_flow);
    limits
}

fn test_limits_with_half_close_timeout(tcp_half_close_timeout_seconds: u64) -> LimitConfig {
    let mut limits = test_limits();
    limits.tcp_half_close_timeout_seconds = Some(tcp_half_close_timeout_seconds);
    limits
}

fn large_payload() -> Vec<u8> {
    patterned_payload(LARGE_PAYLOAD_LEN)
}

fn patterned_payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

fn create_temp_dir() -> Result<PathBuf, TestError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("uk-e2e-{}-{now}-{id}", process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_private_key(path: &Path) -> io::Result<()> {
    write_private_key_contents(path, KEY_PEM)
}

fn write_private_key_contents(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)?;
    restrict_private_key_permissions(path)
}

#[cfg(unix)]
fn restrict_private_key_permissions(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_private_key_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
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

fn allow_ipv6_loopback_policy(port: u16) -> String {
    format!(
        r#"
        [[rules]]
        action = "allow"
        cidr = "::1/128"
        port_start = {port}
        port_end = {port}
        "#
    )
}

fn allow_default_group_loopback_policy(port: u16) -> String {
    allow_group_loopback_policy("default", port)
}

fn allow_admin_group_loopback_policy(port: u16) -> String {
    allow_group_loopback_policy("admins", port)
}

fn allow_group_loopback_policy(group: &str, port: u16) -> String {
    format!(
        r#"
        [[rules]]
        action = "allow"
        policy_group = "{group}"
        cidr = "127.0.0.1/32"
        port_start = {port}
        port_end = {port}
        "#
    )
}

fn allow_loopback_any_port_policy() -> String {
    r#"
        [[rules]]
        action = "allow"
        cidr = "127.0.0.1/32"
        "#
    .to_owned()
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
