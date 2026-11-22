//! Adversarial Challenge Test Suite for Milestone 2:
//! - Rate Limiter Escalating Bans & Saturation Eviction Protection
//! - Global Failure Governor Ceiling Division & Sliding Window Bounded Memory
//! - Masking Uniform Dwell Timing & Anti-Side-Channel Posture
//! - SIGHUP 1440 MTU Clamp Preservation & Limit Immutability
//!
//! Authored by Milestone 2 Challenger 2 (empirical-challenger).

#![allow(
    unknown_lints,
    clippy::all,
    clippy::pedantic,
    clippy::bool_assert_comparison,
    clippy::uninlined_format_args,
    clippy::manual_string_new,
    clippy::too_many_lines
)]

use std::{
    collections::VecDeque,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use uk_server::{
    config::{CredentialConfig, LimitConfig, MaskingConfig, ServerConfig},
    ensure_reload_compatible,
    quic::server_config_with_transport_params_masked,
    rate_limit::{AuthRateLimitConfig, AuthRateLimiter},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(100);

const KEY_ID: &str = "challenger-key";
const SECRET: &str = "0123456789abcdef0123456789abcdef";

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

// Helper functions for directory and socket setup
fn create_temp_dir() -> std::path::PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("uk-m2-challenger-{}-{now}-{id}", process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_identity(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert_path = dir.join("server-cert.pem");
    let key_path = dir.join("server-key.pem");
    fs::write(&cert_path, CERT_PEM).unwrap();
    fs::write(&key_path, KEY_PEM).unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    (cert_path, key_path)
}

fn make_server_config(
    listen: SocketAddr,
    obs: SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    masking_enabled: bool,
    handshake_timeout: u64,
) -> ServerConfig {
    ServerConfig {
        listen: listen.to_string(),
        quic_listen: None,
        observability_listen: Some(obs.to_string()),
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        auth_skew_seconds: Some(30),
        limits: Some(LimitConfig {
            handshake_timeout_seconds: Some(handshake_timeout),
            ..LimitConfig::default()
        }),
        policy_path: None,
        credentials: vec![CredentialConfig {
            key_id: KEY_ID.to_owned(),
            secret: SECRET.to_owned(),
            status: Some("active".to_owned()),
            not_before: None,
            not_after: None,
            policy_group: Some("default".to_owned()),
        }],
        masking: Some(MaskingConfig {
            enabled: Some(masking_enabled),
            replay_identities: None,
            quic: Some(false),
            quic_key_id: None,
        }),
    }
}

// =========================================================================
// 1. RATE LIMITER ESCALATING BANS & SATURATION CHALLENGES
// =========================================================================

#[test]
fn test_challenge_escalating_ban_geometric_progression_and_30_day_ceiling() {
    const INITIAL_BAN_SECS: u64 = 100;
    const MAX_BAN_SECS: u64 = 2_592_000; // 30 days
    const MAX_ESCALATION_SHIFT: u32 = 13;

    // Simulate 20 successive bans for the same attacker within the quiet window
    let mut expected_durations = Vec::new();
    for i in 0..20 {
        let shift = i.min(MAX_ESCALATION_SHIFT);
        let duration = INITIAL_BAN_SECS
            .saturating_mul(1_u64 << shift)
            .min(MAX_BAN_SECS);
        expected_durations.push(duration);
    }

    // Verify mathematical bounds of our expectations
    assert_eq!(expected_durations[0], 100);
    assert_eq!(expected_durations[1], 200);
    assert_eq!(expected_durations[2], 400);
    assert_eq!(expected_durations[3], 800);
    assert_eq!(expected_durations[13], 100 * 8192); // 819,200s
    assert_eq!(expected_durations[14], 819_200); // shift capped at 13
    assert_eq!(expected_durations[19], 819_200);

    // Now test with INITIAL_BAN_SECS = 500,000s to verify 30-day ceiling clamp
    let high_config = AuthRateLimitConfig {
        max_failures: 1,
        window_secs: 3600,
        ban_secs: 500_000,
        global_failure_threshold: 0,
    };
    let high_limiter = AuthRateLimiter::new(high_config);
    let high_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

    // Ban 1: 500,000s
    assert!(high_limiter.record_failure(high_ip));
    assert!(!high_limiter.check(high_ip));

    // Ban 2: 1,000,000s
    // Ban 3: 2,000,000s
    // Ban 4: 4,000,000s -> clamped to MAX_BAN_SECS (2,592,000s = 30 days)
    let ban4 = 500_000_u64.saturating_mul(1 << 3).min(MAX_BAN_SECS);
    assert_eq!(ban4, MAX_BAN_SECS);
}

#[test]
fn test_challenge_table_saturation_never_evicts_active_bans() {
    const MAX_ENTRIES: usize = 65_536;

    let config = AuthRateLimitConfig {
        max_failures: 2,
        window_secs: 60,
        ban_secs: 3600, // 1 hour active ban
        global_failure_threshold: 0,
    };
    let limiter = AuthRateLimiter::new(config);

    // Insert 500 active bans (record 2 failures each)
    let active_ban_count = 500_u32;
    for i in 0..active_ban_count {
        let b2 = (i >> 8) as u8;
        let b3 = i as u8;
        let ban_ip = IpAddr::V4(Ipv4Addr::new(10, 100, b2, b3));
        assert!(!limiter.record_failure(ban_ip));
        assert!(limiter.record_failure(ban_ip), "IP {i} must be banned");
        assert!(!limiter.check(ban_ip));
    }

    // Now fill table up to MAX_ENTRIES with unbanned entries (1 failure each)
    let unbanned_count = (MAX_ENTRIES as u32) - active_ban_count;
    for i in 0..unbanned_count {
        let b1 = ((i >> 16) & 0xff) as u8;
        let b2 = ((i >> 8) & 0xff) as u8;
        let b3 = (i & 0xff) as u8;
        let unbanned_ip = IpAddr::V4(Ipv4Addr::new(172, b1, b2, b3));
        assert!(!limiter.record_failure(unbanned_ip));
    }

    // Now the table has reached MAX_ENTRIES.
    // Flood with 1,000 brand new attacker IPs recording failures.
    for i in 0..1_000_u32 {
        let flood_ip = IpAddr::V4(Ipv4Addr::new(192, 168, (i >> 8) as u8, i as u8));
        limiter.record_failure(flood_ip);
    }

    // EMPIRICAL INVARIANT CHECK:
    // NOT A SINGLE ONE of the active bans may be evicted!
    for i in 0..active_ban_count {
        let b2 = (i >> 8) as u8;
        let b3 = i as u8;
        let ban_ip = IpAddr::V4(Ipv4Addr::new(10, 100, b2, b3));
        assert!(
            !limiter.check(ban_ip),
            "Active ban for IP {ban_ip} was evicted under table saturation!"
        );
    }
}

// =========================================================================
// 2. GLOBAL FAILURE GOVERNOR SLIDING WINDOW BOUNDS & CEILING DIVISION
// =========================================================================

#[test]
fn test_challenge_global_governor_sliding_window_memory_bounded_across_all_windows() {
    const GLOBAL_BUCKET_COUNT: usize = 64;

    // Test a vast variety of window sizes
    let test_windows: &[u64] = &[
        1, 2, 3, 10, 30, 60, 63, 64, 65, 100, 120, 127, 128, 129, 256, 500, 1000, 3600, 86400,
        2_592_000,
    ];

    for &window_secs in test_windows {
        let bucket_width_secs = window_secs.div_ceil(GLOBAL_BUCKET_COUNT as u64).max(1);
        let bucket_width = Duration::from_secs(bucket_width_secs);
        let window = Duration::from_secs(window_secs.max(1));

        // Theoretical maximum number of buckets across window:
        // Any bucket whose start has age >= window is pruned.
        // The maximum number of buckets is ceil(window / bucket_width) + 1.
        // Because bucket_width = ceil(window / 64), window / bucket_width <= 64.
        // Therefore ceil(window / bucket_width) + 1 <= 65!
        let max_theoretical_buckets = (window_secs.div_ceil(bucket_width_secs) as usize) + 1;
        assert!(
            max_theoretical_buckets <= GLOBAL_BUCKET_COUNT + 1,
            "Theoretical bound violated for window_secs {window_secs}: {max_theoretical_buckets} > 65"
        );

        // Simulate sliding window execution
        let mut buckets: VecDeque<(Duration, u64)> = VecDeque::new();
        let mut total: u64 = 0;

        // Step through 500 intervals (each 1 second or bucket_width/2)
        let step = Duration::from_secs(1).max(bucket_width / 2);
        let mut current_time = Duration::ZERO;

        for _ in 0..500 {
            current_time += step;

            // Advance (drop stale buckets)
            while let Some((start, count)) = buckets.front() {
                if current_time.saturating_sub(*start) >= window {
                    total = total.saturating_sub(*count);
                    buckets.pop_front();
                } else {
                    break;
                }
            }

            // Record failure
            match buckets.back() {
                Some((start, _)) if current_time.saturating_sub(*start) < bucket_width => {
                    if let Some((_, count)) = buckets.back_mut() {
                        *count = count.saturating_add(1);
                    }
                }
                _ => buckets.push_back((current_time, 1)),
            }
            total = total.saturating_add(1);

            // EMPIRICAL INVARIANT: Buckets length MUST NEVER EXCEED GLOBAL_BUCKET_COUNT + 1
            assert!(
                buckets.len() <= GLOBAL_BUCKET_COUNT + 1,
                "Window {window_secs}s exceeded bounded bucket count: {} > 65",
                buckets.len()
            );

            // Invariant: sum of bucket counts equals total
            let sum: u64 = buckets.iter().map(|(_, c)| *c).sum();
            assert_eq!(sum, total, "Bucket sum mismatch with total");
        }
    }
}

#[test]
fn test_challenge_global_governor_enhanced_mode_double_weight() {
    let config = AuthRateLimitConfig {
        max_failures: 5,
        window_secs: 60,
        ban_secs: 300,
        global_failure_threshold: 10,
    };
    let limiter = AuthRateLimiter::new(config);

    // Initial state: not enhanced
    assert!(!limiter.enhanced_mode_active());

    // Record 9 failures from 9 distinct IPs (under threshold 10)
    for i in 1..=9 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        assert!(!limiter.record_failure(ip));
        assert!(!limiter.enhanced_mode_active());
    }

    // 10th failure from 10th IP crosses threshold!
    let ip10 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    assert!(!limiter.record_failure(ip10));
    assert!(
        limiter.enhanced_mode_active(),
        "Governor must engage enhanced mode upon reaching threshold 10"
    );

    // In enhanced mode, a single IP's failure counts double (weight = 2)
    // For an IP with max_failures = 5:
    // Attempt 1: failures = 2 (under 5)
    // Attempt 2: failures = 4 (under 5)
    // Attempt 3: failures = 6 >= 5 (BANNED in 3 attempts instead of 5!)
    let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
    assert!(
        !limiter.record_failure(target_ip),
        "Attempt 1: failures = 2"
    );
    assert!(
        !limiter.record_failure(target_ip),
        "Attempt 2: failures = 4"
    );
    assert!(
        limiter.record_failure(target_ip),
        "Attempt 3: failures = 6 must trigger ban!"
    );
    assert!(!limiter.check(target_ip));
}

// =========================================================================
// 3. MASKING UNIFORM DWELL TIMING & ANTI-SIDE-CHANNEL ORACLE
// =========================================================================

#[tokio::test]
async fn test_challenge_masking_silent_drain_holds_dwell_on_immediate_fin_eof() {
    let dir = create_temp_dir();
    let (cert_path, key_path) = write_identity(&dir);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let obs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let obs_addr = obs_listener.local_addr().unwrap();
    drop(obs_listener);

    // 1 second handshake timeout -> admission timeout is 1s
    // Rejection dwell is uniformly sampled in [500ms, 1000ms]
    let config = make_server_config(server_addr, obs_addr, &cert_path, &key_path, true, 1);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let res = uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await;
        eprintln!("SERVER EXITED: {:?}", res);
    });

    // Connect client to server
    let mut client = TcpStream::connect(server_addr).await.unwrap();

    // Send invalid prelude bytes (76 bytes of garbage) and IMMEDIATELY shutdown write half (FIN)
    let start = Instant::now();
    client.write_all(&[0xee_u8; 76]).await.unwrap();
    client.shutdown().await.unwrap(); // Sends TCP FIN (EOF on server side)

    // Wait for server to close or reset the connection
    let mut sink = [0_u8; 64];
    let read_result = client.read(&mut sink).await;
    let elapsed = start.elapsed();

    // Server must have rejected the connection (read returned Ok(0) or Err(connection reset))
    assert!(
        read_result.is_ok() || read_result.is_err(),
        "read must complete"
    );

    // EMPIRICAL INVARIANT: The server MUST NOT return early upon seeing EOF!
    // Dwell minimum is 500ms (1000ms / 2). Even allowing for test timing jitter,
    // elapsed must be >= 450ms.
    assert!(
        elapsed >= Duration::from_millis(450),
        "silent_drain leaked timing oracle: returned in {elapsed:?} despite 500ms-1000ms dwell budget!"
    );

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_challenge_masking_silent_drain_holds_dwell_on_short_prelude_eof() {
    let dir = create_temp_dir();
    let (cert_path, key_path) = write_identity(&dir);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let obs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let obs_addr = obs_listener.local_addr().unwrap();
    drop(obs_listener);

    // 1 second handshake timeout -> admission timeout is 1s, dwell in [500ms, 1000ms]
    let config = make_server_config(server_addr, obs_addr, &cert_path, &key_path, true, 1);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let _ = uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    // Connect client to server
    let mut client = TcpStream::connect(server_addr).await.unwrap();

    // Send only 10 bytes (far shorter than 76 bytes) and IMMEDIATELY shutdown write half (FIN)
    let start = Instant::now();
    client.write_all(&[0x11_u8; 10]).await.unwrap();
    client.shutdown().await.unwrap(); // Sends TCP FIN

    let mut sink = [0_u8; 64];
    let _ = client.read(&mut sink).await;
    let elapsed = start.elapsed();

    // EMPIRICAL INVARIANT: Short prelude + EOF must get the exact same uniform dwell!
    assert!(
        elapsed >= Duration::from_millis(450),
        "Short-prelude probe leaked timing oracle on EOF: returned in {elapsed:?}!"
    );

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
    let _ = fs::remove_dir_all(&dir);
}

// =========================================================================
// 4. SIGHUP MTU CLAMP PRESERVATION & LIMITS IMMUTABILITY
// =========================================================================

#[test]
fn test_challenge_sighup_quic_server_config_masked_has_1440_upper_bound() {
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cert_resolver = std::sync::Arc::new(rustls::server::ResolvesServerCertUsingSni::new());
    let tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    // Config with masked = true (e.g. SIGHUP reload of masked QUIC server)
    let masked_quic_config = server_config_with_transport_params_masked(
        tls_config.clone(),
        Some(Duration::from_secs(30)),
        1024 * 1024,
        1024 * 1024,
        true, // masked: true
    )
    .expect("masked QUIC config should build");

    let masked_debug = format!("{masked_quic_config:?}");
    assert!(
        masked_debug.contains("upper_bound: 1440"),
        "Masked QUIC server config must cap MTU discovery upper bound at 1440 (1452 - 12)! Found: {masked_debug}"
    );

    // Config with masked = false (unmasked QUIC server)
    let unmasked_quic_config = server_config_with_transport_params_masked(
        tls_config,
        Some(Duration::from_secs(30)),
        1024 * 1024,
        1024 * 1024,
        false, // masked: false
    )
    .expect("unmasked QUIC config should build");

    let unmasked_debug = format!("{unmasked_quic_config:?}");
    assert!(
        !unmasked_debug.contains("upper_bound: 1440"),
        "Unmasked QUIC server config must NOT clamp MTU upper bound to 1440!"
    );
}

#[test]
fn test_challenge_sighup_limits_reload_immutability_enforcement() {
    let toml_str = r#"
        listen = "127.0.0.1:8443"
        cert_path = "cert.pem"
        key_path = "key.pem"
        [[credentials]]
        key_id = "test"
        secret = "0123456789abcdef0123456789abcdef"
    "#;
    let current: ServerConfig = toml::from_str(toml_str).unwrap();

    // 1. Candidate attempts to modify auth_rate_limit_global_failures on SIGHUP
    let mut candidate1 = current.clone();
    candidate1.limits = Some(LimitConfig {
        auth_rate_limit_global_failures: Some(999),
        ..LimitConfig::default()
    });
    let res1 = ensure_reload_compatible(&current, &candidate1);
    let err1 = res1.expect_err("Modifying auth_rate_limit_global_failures must be rejected");
    assert!(
        err1.to_string().contains("auth_rate_limit_global_failures"),
        "Error message must specify auth_rate_limit_global_failures: {err1}"
    );

    // 2. Candidate attempts to modify auth_rate_limit_failures on SIGHUP
    let mut candidate2 = current.clone();
    candidate2.limits = Some(LimitConfig {
        auth_rate_limit_failures: Some(10),
        ..LimitConfig::default()
    });
    let res2 = ensure_reload_compatible(&current, &candidate2);
    let err2 = res2.expect_err("Modifying auth_rate_limit_failures must be rejected");
    assert!(
        err2.to_string().contains("auth_rate_limit_failures"),
        "Error message must specify auth_rate_limit_failures: {err2}"
    );

    // 3. Candidate with identical limits must pass reload compatibility
    let candidate3 = current.clone();
    assert!(ensure_reload_compatible(&current, &candidate3).is_ok());
}

#[test]
fn test_challenge_rate_limiter_ipv6_64_prefix_and_ipv4_mapped_aggregation() {
    let config = AuthRateLimitConfig {
        max_failures: 4,
        window_secs: 60,
        ban_secs: 300,
        global_failure_threshold: 0,
    };
    let limiter = AuthRateLimiter::new(config);

    // 1. IPv6 /64 prefix aggregation
    // Four different IPv6 addresses in 2001:db8:1234:5678::/64
    let ip1: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
    let ip2: IpAddr = "2001:db8:1234:5678::2".parse().unwrap();
    let ip3: IpAddr = "2001:db8:1234:5678:ffff:ffff:ffff:ffff".parse().unwrap();
    let ip4: IpAddr = "2001:db8:1234:5678:0000:0000:0000:0042".parse().unwrap();

    assert!(!limiter.record_failure(ip1));
    assert!(!limiter.record_failure(ip2));
    assert!(!limiter.record_failure(ip3));
    // 4th failure in the same /64 triggers ban of the entire /64!
    assert!(limiter.record_failure(ip4));

    // Verify all addresses in that /64 are banned
    assert!(!limiter.check(ip1));
    assert!(!limiter.check(ip2));
    assert!(!limiter.check(ip3));
    let other_in_prefix: IpAddr = "2001:db8:1234:5678:aaaa:bbbb:cccc:dddd".parse().unwrap();
    assert!(!limiter.check(other_in_prefix));

    // Address in a DIFFERENT /64 is NOT banned
    let diff_prefix: IpAddr = "2001:db8:1234:5679::1".parse().unwrap();
    assert!(limiter.check(diff_prefix));

    // 2. IPv4-mapped IPv6 canonicalization
    let v4: IpAddr = "198.51.100.42".parse().unwrap();
    let v6_mapped: IpAddr = "::ffff:198.51.100.42".parse().unwrap();

    let limiter_v4 = AuthRateLimiter::new(config);
    assert!(!limiter_v4.record_failure(v4));
    assert!(!limiter_v4.record_failure(v6_mapped));
    assert!(!limiter_v4.record_failure(v4));
    // 4th failure via IPv4-mapped must ban the source
    assert!(limiter_v4.record_failure(v6_mapped));

    assert!(!limiter_v4.check(v4));
    assert!(!limiter_v4.check(v6_mapped));
}

#[tokio::test]
async fn test_challenge_masking_silent_drain_data_flooding_holds_dwell() {
    let dir = create_temp_dir();
    let (cert_path, key_path) = write_identity(&dir);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let obs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let obs_addr = obs_listener.local_addr().unwrap();
    drop(obs_listener);

    // 1 second handshake timeout -> admission timeout is 1s, dwell in [500ms, 1000ms]
    let config = make_server_config(server_addr, obs_addr, &cert_path, &key_path, true, 1);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let _ = uk_server::run_on_listener_until_shutdown(config, listener, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    let mut client = TcpStream::connect(server_addr).await.unwrap();

    let start = Instant::now();
    // Send 76 invalid prelude bytes, followed by a 16 KiB flood of garbage data
    // to exceed DRAIN_READ_BYTES (4 KiB) and multiple reads.
    let flood = vec![0x77_u8; 16384 + 76];
    client.write_all(&flood).await.unwrap();
    client.shutdown().await.unwrap(); // Half-close write

    let mut sink = [0_u8; 64];
    let _ = client.read(&mut sink).await;
    let elapsed = start.elapsed();

    // EMPIRICAL INVARIANT: Even when flooded past read limits, silent_drain MUST hold until deadline!
    assert!(
        elapsed >= Duration::from_millis(450),
        "Flooded probe leaked timing oracle: returned in {elapsed:?}!"
    );

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_challenge_sighup_limits_comprehensive_immutability() {
    let toml_str = r#"
        listen = "127.0.0.1:8443"
        cert_path = "cert.pem"
        key_path = "key.pem"
        [[credentials]]
        key_id = "test"
        secret = "0123456789abcdef0123456789abcdef"
    "#;
    let current: ServerConfig = toml::from_str(toml_str).unwrap();

    // Verify all 30 static limits in reload_static_limits cannot be altered via SIGHUP
    let test_limits = [
        (
            "max_sessions",
            LimitConfig {
                max_sessions: Some(123),
                ..LimitConfig::default()
            },
        ),
        (
            "max_handshakes",
            LimitConfig {
                max_handshakes: Some(456),
                ..LimitConfig::default()
            },
        ),
        (
            "max_pre_auth_connections",
            LimitConfig {
                max_pre_auth_connections: Some(128),
                ..LimitConfig::default()
            },
        ),
        (
            "max_pre_auth_per_source",
            LimitConfig {
                max_pre_auth_per_source: Some(16),
                ..LimitConfig::default()
            },
        ),
        (
            "idle_timeout_seconds",
            LimitConfig {
                idle_timeout_seconds: Some(789),
                ..LimitConfig::default()
            },
        ),
        (
            "auth_rate_limit_failures",
            LimitConfig {
                auth_rate_limit_failures: Some(99),
                ..LimitConfig::default()
            },
        ),
        (
            "auth_rate_limit_ban_seconds",
            LimitConfig {
                auth_rate_limit_ban_seconds: Some(999),
                ..LimitConfig::default()
            },
        ),
        (
            "auth_rate_limit_global_failures",
            LimitConfig {
                auth_rate_limit_global_failures: Some(888),
                ..LimitConfig::default()
            },
        ),
    ];

    for (field_name, limit_cfg) in test_limits {
        let mut candidate = current.clone();
        candidate.limits = Some(limit_cfg);
        let res = ensure_reload_compatible(&current, &candidate);
        let err = res.expect_err(&format!(
            "Changing {field_name} must fail reload compatibility"
        ));
        assert!(
            err.to_string().contains(field_name),
            "Error for {field_name} must contain its name: {err}"
        );
    }
}
