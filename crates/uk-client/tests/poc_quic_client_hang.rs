//! Hardened Invariant Verification for FINDING-16: Bounded accept_bi Timeout in Client QUIC Connect.
//!
//! Verifies that when a server accepts a QUIC connection but never opens the
//! bidirectional control stream, `connect_with_client_config` with a bounded attempt budget
//! times out and aborts promptly without hanging indefinitely, preventing connection pool resource exhaustion.

#![allow(unknown_lints, clippy::all, clippy::pedantic)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

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

#[tokio::test]
async fn test_poc_finding_16_client_quic_accept_bi_unbounded_hang() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let certs = vec![CertificateDer::from_pem_slice(CERT_PEM.as_bytes()).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM.as_bytes()).unwrap();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    server_crypto.alpn_protocols = vec![uk_proto::ALPN_PROTOCOL.to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
    ));

    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_endpoint = quinn::Endpoint::server(server_config, server_addr).unwrap();
    let local_addr = server_endpoint.local_addr().unwrap();

    // Spawn server that accepts connection but NEVER calls open_bi():
    let mut server_tasks = tokio::task::JoinSet::new();
    server_tasks.spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            if let Ok(conn) = incoming.await {
                // Server stalls here: keeps connection open but never opens bidirectional control stream!
                tokio::time::sleep(Duration::from_millis(500)).await;
                conn.close(0u32.into(), b"done");
            }
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![uk_proto::ALPN_PROTOCOL.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));

    // Connect with a bounded attempt budget (150ms) to a server that stalls accept_bi:
    let start = std::time::Instant::now();
    let result = uk_client::quic::connect_with_client_config(
        client_config,
        &local_addr.to_string(),
        "localhost",
        Some(Duration::from_millis(150)),
        None,
    )
    .await;
    let elapsed = start.elapsed();

    // Invariant: connect_with_client_config must return an error within budget rather than hanging indefinitely.
    assert!(
        result.is_err(),
        "Hardened invariant: connect_with_client_config must return error on stalled control stream"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "Hardened invariant: connect_with_client_config must abort promptly within budget, took {elapsed:?}"
    );
    let err_str = result.err().unwrap().to_string();
    assert!(
        err_str.contains("exceeded budget") || err_str.contains("failed to accept"),
        "Hardened invariant: expected budget timeout error, got: {err_str}"
    );

    server_tasks.abort_all();
    while server_tasks.join_next().await.is_some() {}
}

#[tokio::test]
async fn test_challenge_quic_client_concurrent_stalling_servers_and_socket_leak_discipline() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let certs = vec![CertificateDer::from_pem_slice(CERT_PEM.as_bytes()).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM.as_bytes()).unwrap();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    server_crypto.alpn_protocols = vec![uk_proto::ALPN_PROTOCOL.to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
    ));

    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_endpoint = quinn::Endpoint::server(server_config, server_addr).unwrap();
    let local_addr = server_endpoint.local_addr().unwrap();

    // Spawn server that repeatedly accepts connections and stalls without opening bidirectional streams
    let child_tasks = Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));
    let child_tasks_server = Arc::clone(&child_tasks);
    let server_task = tokio::spawn(async move {
        while let Some(incoming) = server_endpoint.accept().await {
            child_tasks_server.lock().await.spawn(async move {
                if let Ok(conn) = incoming.await {
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    conn.close(0u32.into(), b"done");
                }
            });
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![uk_proto::ALPN_PROTOCOL.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));

    // Spawn 10 concurrent clients with a 100ms attempt budget
    let mut handles = Vec::new();
    let start_all = std::time::Instant::now();

    for _ in 0..10 {
        let config = client_config.clone();
        let addr_str = local_addr.to_string();
        let handle = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let res = uk_client::quic::connect_with_client_config(
                config,
                &addr_str,
                "localhost",
                Some(Duration::from_millis(100)),
                None,
            )
            .await;
            let elapsed = start.elapsed();
            (res, elapsed)
        });
        handles.push(handle);
    }

    // Await all concurrent client connections
    for handle in handles {
        let (res, elapsed) = handle.await.unwrap();
        assert!(
            res.is_err(),
            "Concurrent client connect must return error on stalled stream"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "Concurrent client took too long: {elapsed:?}"
        );
        let err_str = res.err().unwrap().to_string();
        assert!(
            err_str.contains("exceeded budget") || err_str.contains("failed to accept"),
            "Expected budget timeout, got: {err_str}"
        );
    }

    let total_elapsed = start_all.elapsed();
    assert!(
        total_elapsed < Duration::from_millis(800),
        "All 10 concurrent timeouts must finish in parallel within 800ms, took {total_elapsed:?}"
    );

    server_task.abort();
    let _ = server_task.await;
    let mut tasks = child_tasks.lock().await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
