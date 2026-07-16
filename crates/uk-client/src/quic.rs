//! QUIC carrier connector for the client.
//!
//! Dials a UK server over QUIC using the shared rustls TLS 1.3 material and
//! `uk/1` ALPN, then hands the server-opened control stream to the
//! carrier-neutral authentication path. The connector resolves the endpoint to
//! a socket address itself (quinn dials socket addresses, not host names) while
//! still presenting the configured server name for certificate verification.

use std::{net::SocketAddr, sync::Arc};

use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, crypto::rustls::QuicClientConfig, default_runtime,
};
use rustls::ClientConfig as RustlsClientConfig;
use tokio::net::lookup_host;
use uk_auth::EXPORTER_LABEL;
use uk_proto::{ALPN_PROTOCOL, BoxedCarrierReader, BoxedCarrierWriter};

type QuicError = Box<dyn std::error::Error + Send + Sync>;

/// Connects to `endpoint` over QUIC, verifies the UK ALPN, and returns the
/// server-opened control stream as carrier-neutral halves plus the exporter.
pub async fn connect(
    rustls_config: RustlsClientConfig,
    endpoint: &str,
    server_name: &str,
) -> Result<(BoxedCarrierReader, BoxedCarrierWriter, [u8; 32]), QuicError> {
    let addr = resolve(endpoint).await?;
    let mut client_endpoint = Endpoint::client(unspecified_addr(addr))
        .map_err(|err| format!("failed to bind local QUIC socket: {err}"))?;
    client_endpoint.set_default_client_config(client_config(rustls_config)?);

    let connection = client_endpoint
        .connect(addr, server_name)
        .map_err(|err| format!("failed to start QUIC connection to {addr}: {err}"))?
        .await
        .map_err(|err| format!("QUIC handshake with {addr} failed: {err}"))?;
    verify_alpn(&connection)?;
    let exporter = exporter(&connection)?;

    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|err| format!("failed to accept QUIC control stream: {err}"))?;
    // Hold the connection open for the session lifetime by leaking it into the
    // endpoint's driver; the send/recv halves keep the connection state alive,
    // and the endpoint is kept alive by the spawned driver task.
    keep_endpoint_alive(client_endpoint);
    Ok((Box::new(recv), Box::new(send), exporter))
}

fn client_config(rustls_config: RustlsClientConfig) -> Result<QuinnClientConfig, QuicError> {
    let crypto = QuicClientConfig::try_from(rustls_config)
        .map_err(|err| format!("QUIC client crypto config rejected: {err}"))?;
    Ok(QuinnClientConfig::new(Arc::new(crypto)))
}

async fn resolve(endpoint: &str) -> Result<SocketAddr, QuicError> {
    lookup_host(endpoint)
        .await
        .map_err(|err| format!("failed to resolve QUIC endpoint {endpoint}: {err}"))?
        .next()
        .ok_or_else(|| format!("QUIC endpoint {endpoint} resolved to no addresses").into())
}

fn unspecified_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    }
}

fn verify_alpn(connection: &quinn::Connection) -> Result<(), QuicError> {
    let handshake = connection
        .handshake_data()
        .ok_or("QUIC connection is missing handshake data")?;
    let negotiated = handshake
        .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
        .and_then(|data| data.protocol.as_deref());
    if negotiated == Some(ALPN_PROTOCOL) {
        Ok(())
    } else {
        Err("UK ALPN protocol was not negotiated".into())
    }
}

fn exporter(connection: &quinn::Connection) -> Result<[u8; 32], QuicError> {
    let mut out = [0_u8; 32];
    connection
        .export_keying_material(&mut out, EXPORTER_LABEL, &[])
        .map_err(|err| format!("QUIC keying-material export failed: {err:?}"))?;
    Ok(out)
}

/// Keeps the client endpoint alive for the connection's lifetime. quinn drives
/// I/O from the endpoint; dropping it would close the connection. The stream
/// halves hold the connection state, so we only need to retain the endpoint.
fn keep_endpoint_alive(endpoint: Endpoint) {
    let _runtime = default_runtime();
    tokio::spawn(async move {
        endpoint.wait_idle().await;
    });
}
