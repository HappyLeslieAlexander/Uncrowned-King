//! End-to-end TCP relay tests.

use std::{
    fs,
    io::{self, BufReader},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Bytes, BytesMut};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Barrier, oneshot},
    task::JoinHandle,
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
    config::ClientConfig, connect_authenticated_carrier, run_handshake, run_socks5_listener,
    run_socks5_listener_until_shutdown,
};
use uk_proto::{
    ALPN_PROTOCOL, ErrorCode, ErrorPayload, Frame, FrameHeader, FrameIoError, FrameLimits,
    FrameType, SettingKey, Settings, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE,
    Target, TcpClose, TcpOpen, UDP_CLOSE_ERROR, UdpClose, UdpOpen, read_frame,
    validate_connection_frame, write_frame,
};
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
const WRONG_SECRET: &str = "fedcba9876543210fedcba9876543210";
const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REPLY_NOT_ALLOWED: u8 = 0x02;
const SOCKS_REPLY_HOST_UNREACHABLE: u8 = 0x04;
const HALF_CLOSE_REQUEST: &[u8] = b"uncrowned king half-close request";
const HALF_CLOSE_RESPONSE: &[u8] = b"uncrowned king half-close response";
const TARGET_HALF_CLOSE_GREETING: &[u8] = b"uncrowned king target half-close greeting";
const TARGET_HALF_CLOSE_LATE_REQUEST: &[u8] = b"uncrowned king target half-close late request";
const TARGET_HALF_CLOSE_TIMEOUT_GREETING: &[u8] =
    b"uncrowned king target half-close timeout greeting";
const LARGE_PAYLOAD_LEN: usize = 128 * 1024 + 123;
const SMALL_FRAME_PAYLOAD_LEN: usize = 8 * 1024 + 37;
const TEST_LOOPBACK_PORT_BASE: u16 = 20_000;
const TEST_LOOPBACK_PORT_SPAN: u16 = 10_000;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
static NEXT_LOOPBACK_PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

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
async fn relays_multiple_udp_targets_over_one_socks5_association() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_multi_target_udp_relay_e2e()).await?
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
async fn reports_protocol_error_for_malformed_tcp_close() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_malformed_tcp_close_error_e2e()).await?
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
async fn closes_existing_flow_after_duplicate_tcp_open() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_duplicate_tcp_open_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_existing_udp_flow_after_duplicate_udp_open() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_duplicate_udp_open_error_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_session_alive_after_unknown_tcp_data() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_unknown_tcp_data_error_e2e()).await?
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
async fn socks_listener_stops_while_server_connect_is_pending() -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_socks_listener_shutdown_during_connect_e2e(),
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
async fn enforces_server_session_limit() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_server_session_limit_e2e()).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_concurrent_socks_flows_over_one_session() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_concurrent_multiplex_e2e()).await?
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
async fn closes_target_when_socks_client_disconnects() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(10), run_client_disconnect_e2e()).await?
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

    socks.write_all(b"uncrowned king e2e").await?;
    let mut echoed = vec![0_u8; "uncrowned king e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"uncrowned king e2e");

    echo_task.await??;
    Ok(())
}

async fn run_udp_relay_e2e() -> Result<(), TestError> {
    init_tracing();

    let (target_addr, echo_task) = spawn_udp_echo_target().await?;
    let harness = RelayHarness::start(Some(allow_loopback_policy(target_addr.port()))).await?;
    let (_socks_control, udp_relay_addr) = open_socks_udp_associate(harness.socks_addr).await?;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let payload = b"uncrowned king udp e2e";

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
    let first_payload = b"uncrowned king udp first target";
    let second_payload = b"uncrowned king udp second target";

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

async fn run_udp_associate_server_unavailable_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    fs::write(&cert_path, CERT_PEM)?;
    let server_addr = unused_loopback_addr().await?;
    let socks_addr = unused_loopback_addr().await?;
    let mut client_task = tokio::spawn(run_socks5_listener(
        ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(1),
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
        },
        socks_addr.to_string(),
    ));
    wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

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
    let first_payload = b"uncrowned king udp allowed target";
    let second_payload = b"uncrowned king udp limited target";

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
    let first_payload = b"uncrowned king udp idle first target";
    let second_payload = b"uncrowned king udp idle second target";

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
    let first_payload = b"uncrowned king server udp idle first";
    let second_payload = b"uncrowned king server udp idle second";

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

    let early_payload = b"uncrowned king early socks data";
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
    request.extend_from_slice(b"uncrowned king early data before open ack");
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

async fn run_server_session_limit_e2e() -> Result<(), TestError> {
    init_tracing();

    let harness = ServerHarness::start(test_limits_with_max_sessions(1)).await?;
    let _held_carrier = connect_tls_carrier_after_probe(&harness).await?;
    let result = run_handshake(harness.client_config(SECRET)).await;

    assert!(
        result.is_err(),
        "second carrier should fail while max_sessions is exhausted"
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

    socks.write_all(b"uncrowned king domain e2e").await?;
    let mut echoed = vec![0_u8; "uncrowned king domain e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"uncrowned king domain e2e");

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

    socks.write_all(b"uncrowned king policy group e2e").await?;
    let mut echoed = vec![0_u8; "uncrowned king policy group e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"uncrowned king policy group e2e");

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

    socks.write_all(b"uncrowned king ipv6 e2e").await?;
    let mut echoed = vec![0_u8; "uncrowned king ipv6 e2e".len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(echoed, b"uncrowned king ipv6 e2e");

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

    let payload = Bytes::from_static(b"session survives unknown flow");
    let keepalive_probe = Frame::new(FrameType::Ping, 0, 0, payload.clone())?;
    write_frame(&mut carrier, &keepalive_probe).await?;

    let reply_frame = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame(&mut carrier, FrameLimits::default()),
    )
    .await??;
    assert_eq!(reply_frame.header.frame_type, FrameType::Pong);
    assert_eq!(reply_frame.header.id, 0);
    assert_eq!(reply_frame.payload, payload);
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
    fs::write(&key_path, KEY_PEM)?;
    let server_addr = unused_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(uk_server::run_until_shutdown(
        ServerConfig {
            listen: server_addr.to_string(),
            cert_path: path_string(&cert_path),
            key_path: path_string(&key_path),
            auth_skew_seconds: Some(30),
            limits: Some(test_limits()),
            policy_path: None,
            credentials: vec![CredentialConfig {
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                status: Some("active".to_owned()),
                not_before: None,
                not_after: None,
                policy_group: Some("default".to_owned()),
            }],
        },
        async {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-server", server_addr, &mut server_task).await?;

    shutdown_tx
        .send(())
        .map_err(|()| "server shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}

async fn run_server_active_session_shutdown_e2e() -> Result<(), TestError> {
    init_tracing();

    let temp_dir = create_temp_dir()?;
    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM)?;
    fs::write(&key_path, KEY_PEM)?;
    let server_addr = unused_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(uk_server::run_until_shutdown(
        ServerConfig {
            listen: server_addr.to_string(),
            cert_path: path_string(&cert_path),
            key_path: path_string(&key_path),
            auth_skew_seconds: Some(30),
            limits: Some(test_limits()),
            policy_path: None,
            credentials: vec![CredentialConfig {
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                status: Some("active".to_owned()),
                not_before: None,
                not_after: None,
                policy_group: Some("default".to_owned()),
            }],
        },
        async {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-server", server_addr, &mut server_task).await?;

    let mut carrier = connect_authenticated_carrier(ClientConfig {
        server_addr: server_addr.to_string(),
        server_addrs: None,
        server_name: "localhost".to_owned(),
        ca_cert_path: path_string(&cert_path),
        key_id: KEY_ID.to_owned(),
        secret: SECRET.to_owned(),
        handshake_timeout_seconds: Some(3),
        socks_handshake_timeout_seconds: Some(3),
        tcp_open_timeout_seconds: Some(3),
        udp_flow_idle_timeout_seconds: None,
        max_pending_open_bytes: None,
        max_socks_connections: None,
        max_buffered_bytes_per_session: None,
        max_buffered_bytes_per_flow: None,
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
    let socks_addr = unused_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut client_task = tokio::spawn(run_socks5_listener_until_shutdown(
        ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(3),
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
        },
        socks_addr.to_string(),
        async {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

    shutdown_tx
        .send(())
        .map_err(|()| "client shutdown receiver dropped")?;
    tokio::time::timeout(Duration::from_secs(3), client_task).await???;
    Ok(())
}

async fn run_socks_listener_shutdown_during_connect_e2e() -> Result<(), TestError> {
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

    let socks_addr = unused_loopback_addr().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut client_task = tokio::spawn(run_socks5_listener_until_shutdown(
        ClientConfig {
            server_addr: server_addr.to_string(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            ca_cert_path: path_string(&cert_path),
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            handshake_timeout_seconds: Some(30),
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(30),
            udp_flow_idle_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
        },
        socks_addr.to_string(),
        async {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

    let mut socks = TcpStream::connect(socks_addr).await?;
    let request = socks_connect_request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
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
        fs::write(&key_path, KEY_PEM)?;
        let policy_path = if let Some(policy_toml) = policy_toml {
            let policy_path = temp_dir.join("policy.toml");
            fs::write(&policy_path, policy_toml)?;
            Some(policy_path)
        } else {
            None
        };
        let server_addr = unused_loopback_addr().await?;
        let mut server_task = tokio::spawn(uk_server::run(ServerConfig {
            listen: server_addr.to_string(),
            cert_path: path_string(&cert_path),
            key_path: path_string(&key_path),
            auth_skew_seconds: Some(auth_skew_seconds),
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
            ca_cert_path: path_string(&self.cert_path),
            key_id: KEY_ID.to_owned(),
            secret: secret.to_owned(),
            handshake_timeout_seconds: Some(3),
            socks_handshake_timeout_seconds: Some(3),
            tcp_open_timeout_seconds: Some(3),
            udp_flow_idle_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
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
    let mut reader = BufReader::new(fs::File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
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
    NonEmptyOpenAck,
    OversizedFrameDuringOpen,
}

impl MalformedFrameServerHarness {
    async fn start() -> Result<Self, TestError> {
        Self::start_with_scenario(MalformedFrameScenario::RelayFrameAfterOpen).await
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
        fs::write(&key_path, KEY_PEM)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let socks_addr = unused_loopback_addr().await?;
        let server_task = tokio::spawn(run_malformed_frame_server(
            server_listener,
            cert_path.clone(),
            key_path,
            scenario,
        ));
        let mut client_task = tokio::spawn(run_socks5_listener(
            ClientConfig {
                server_addr: server_addr.to_string(),
                server_addrs: None,
                server_name: "localhost".to_owned(),
                ca_cert_path: path_string(&cert_path),
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                handshake_timeout_seconds: Some(3),
                socks_handshake_timeout_seconds: Some(3),
                tcp_open_timeout_seconds: Some(3),
                udp_flow_idle_timeout_seconds: None,
                max_pending_open_bytes: None,
                max_socks_connections: None,
                max_buffered_bytes_per_session: None,
                max_buffered_bytes_per_flow: None,
            },
            socks_addr.to_string(),
        ));
        wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

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
        fs::write(&key_path, KEY_PEM)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let socks_addr = unused_loopback_addr().await?;
        let server_task = tokio::spawn(run_client_buffered_limit_server(
            server_listener,
            cert_path.clone(),
            key_path,
        ));
        let mut client_task = tokio::spawn(run_socks5_listener(
            ClientConfig {
                server_addr: server_addr.to_string(),
                server_addrs: None,
                server_name: "localhost".to_owned(),
                ca_cert_path: path_string(&cert_path),
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                handshake_timeout_seconds: Some(3),
                socks_handshake_timeout_seconds: Some(3),
                tcp_open_timeout_seconds: Some(3),
                udp_flow_idle_timeout_seconds: None,
                max_pending_open_bytes: None,
                max_socks_connections: None,
                max_buffered_bytes_per_session: None,
                max_buffered_bytes_per_flow: Some(1),
            },
            socks_addr.to_string(),
        ));
        wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

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

impl UdpStreamFallbackDisabledServerHarness {
    async fn start() -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        fs::write(&key_path, KEY_PEM)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let socks_addr = unused_loopback_addr().await?;
        let server_task = tokio::spawn(run_udp_stream_fallback_disabled_server(
            server_listener,
            cert_path.clone(),
            key_path,
        ));
        let mut client_task = tokio::spawn(run_socks5_listener(
            ClientConfig {
                server_addr: server_addr.to_string(),
                server_addrs: None,
                server_name: "localhost".to_owned(),
                ca_cert_path: path_string(&cert_path),
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                handshake_timeout_seconds: Some(3),
                socks_handshake_timeout_seconds: Some(3),
                tcp_open_timeout_seconds: Some(3),
                udp_flow_idle_timeout_seconds: None,
                max_pending_open_bytes: None,
                max_socks_connections: None,
                max_buffered_bytes_per_session: None,
                max_buffered_bytes_per_flow: None,
            },
            socks_addr.to_string(),
        ));
        wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

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

impl PendingOpenCancelServerHarness {
    async fn start() -> Result<Self, TestError> {
        Self::start_with_tcp_open_timeout(30).await
    }

    async fn start_with_tcp_open_timeout(tcp_open_timeout_seconds: u64) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        fs::write(&key_path, KEY_PEM)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let socks_addr = unused_loopback_addr().await?;
        let server_task = tokio::spawn(run_pending_open_cancel_server(
            server_listener,
            cert_path.clone(),
            key_path,
        ));
        let mut client_task = tokio::spawn(run_socks5_listener(
            ClientConfig {
                server_addr: server_addr.to_string(),
                server_addrs: None,
                server_name: "localhost".to_owned(),
                ca_cert_path: path_string(&cert_path),
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                handshake_timeout_seconds: Some(3),
                socks_handshake_timeout_seconds: Some(3),
                tcp_open_timeout_seconds: Some(tcp_open_timeout_seconds),
                udp_flow_idle_timeout_seconds: None,
                max_pending_open_bytes: None,
                max_socks_connections: None,
                max_buffered_bytes_per_session: None,
                max_buffered_bytes_per_flow: None,
            },
            socks_addr.to_string(),
        ));
        wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

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
}

impl MissingPongServerHarness {
    async fn start() -> Result<Self, TestError> {
        Self::start_with_behavior(PongBehavior::Missing).await
    }

    async fn start_with_empty_pong() -> Result<Self, TestError> {
        Self::start_with_behavior(PongBehavior::Empty).await
    }

    async fn start_with_behavior(pong_behavior: PongBehavior) -> Result<Self, TestError> {
        let temp_dir = create_temp_dir()?;
        let cert_path = temp_dir.join("server-cert.pem");
        let key_path = temp_dir.join("server-key.pem");
        fs::write(&cert_path, CERT_PEM)?;
        fs::write(&key_path, KEY_PEM)?;

        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server_addr = server_listener.local_addr()?;
        let socks_addr = unused_loopback_addr().await?;
        let server_task = tokio::spawn(run_missing_pong_server(
            server_listener,
            cert_path.clone(),
            key_path,
            pong_behavior,
        ));
        let mut client_task = tokio::spawn(run_socks5_listener(
            ClientConfig {
                server_addr: server_addr.to_string(),
                server_addrs: None,
                server_name: "localhost".to_owned(),
                ca_cert_path: path_string(&cert_path),
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                handshake_timeout_seconds: Some(3),
                socks_handshake_timeout_seconds: Some(3),
                tcp_open_timeout_seconds: Some(3),
                udp_flow_idle_timeout_seconds: None,
                max_pending_open_bytes: None,
                max_socks_connections: None,
                max_buffered_bytes_per_session: None,
                max_buffered_bytes_per_flow: None,
            },
            socks_addr.to_string(),
        ));
        wait_for_listener("uk-client", socks_addr, &mut client_task).await?;

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
    assert_eq!(response.header.id, 0);
    let mut payload = response.payload;
    Ok(ErrorPayload::decode(&mut payload)?.code)
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

async fn run_pending_open_cancel_server(
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

async fn run_udp_stream_fallback_disabled_server(
    listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<(), TestError> {
    let mut settings = fake_server_settings();
    settings.set(SettingKey::SupportsUdpStreamFallback, 0);
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

    if matches!(pong_behavior, PongBehavior::Empty) {
        let empty_pong_frame = Frame::new(FrameType::Pong, 0, 0, Bytes::new())?;
        write_frame(&mut stream, &empty_pong_frame).await?;
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
    let (tcp, _) = listener.accept().await?;
    tcp.set_nodelay(true)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(&cert_path, &key_path)?));
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
    let mut reader = BufReader::new(fs::File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| "missing private key".into())
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
        )
        .await
    }

    async fn start_with_limits(
        policy_toml: Option<String>,
        limits: LimitConfig,
    ) -> Result<Self, TestError> {
        Self::start_with_client_options(policy_toml, limits, 3, None, None).await
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
        )
        .await
    }

    async fn start_with_client_options(
        policy_toml: Option<String>,
        limits: LimitConfig,
        socks_handshake_timeout_seconds: u64,
        max_socks_connections: Option<u64>,
        udp_flow_idle_timeout_seconds: Option<u64>,
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
                server_addrs: None,
                server_name: "localhost".to_owned(),
                ca_cert_path: path_string(&cert_path),
                key_id: KEY_ID.to_owned(),
                secret: SECRET.to_owned(),
                handshake_timeout_seconds: Some(3),
                socks_handshake_timeout_seconds: Some(socks_handshake_timeout_seconds),
                tcp_open_timeout_seconds: Some(3),
                udp_flow_idle_timeout_seconds,
                max_pending_open_bytes: None,
                max_socks_connections,
                max_buffered_bytes_per_session: None,
                max_buffered_bytes_per_flow: None,
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

async fn spawn_udp_echo_target()
-> Result<(SocketAddr, tokio::task::JoinHandle<Result<(), TestError>>), TestError> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0_u8; 1024];
        let (read, peer) = socket.recv_from(&mut buf).await?;
        socket.send_to(&buf[..read], peer).await?;
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

async fn open_socks_udp_associate_reply(
    socks_addr: SocketAddr,
) -> Result<(TcpStream, [u8; 4]), TestError> {
    let mut socks = TcpStream::connect(socks_addr).await?;
    socks
        .write_all(&[
            0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00,
        ])
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

async fn read_open_ack(
    carrier: &mut ClientTlsStream<TcpStream>,
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

async fn read_udp_open_ack(
    carrier: &mut ClientTlsStream<TcpStream>,
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

async fn assert_flow_error(
    carrier: &mut ClientTlsStream<TcpStream>,
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

async fn assert_tcp_close(
    carrier: &mut ClientTlsStream<TcpStream>,
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

async fn assert_udp_close(
    carrier: &mut ClientTlsStream<TcpStream>,
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
    for _ in 0..10_000 {
        let offset = NEXT_LOOPBACK_PORT_OFFSET.fetch_add(1, Ordering::Relaxed);
        let port = TEST_LOOPBACK_PORT_BASE + offset % TEST_LOOPBACK_PORT_SPAN;
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if let Ok(listener) = TcpListener::bind(addr).await {
            drop(listener);
            return Ok(addr);
        }
    }
    Err("no available loopback port in test range".into())
}

fn test_limits() -> LimitConfig {
    LimitConfig {
        max_pre_auth_bytes: Some(4096),
        max_frame_size: Some(65_536),
        max_sessions: Some(32),
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
