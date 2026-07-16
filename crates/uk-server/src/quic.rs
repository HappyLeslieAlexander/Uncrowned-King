//! QUIC carrier helpers for the server.
//!
//! The QUIC carrier reuses the same rustls TLS 1.3 material and ALPN (`uk/1`)
//! as the TLS/TCP carrier. UK frames travel over a single bidirectional QUIC
//! stream that the server opens after the handshake completes. The server
//! opens it (rather than the client) because UK sends `AUTH_CHALLENGE` first,
//! and a QUIC stream only becomes visible to the peer once its opener writes;
//! opening server-side keeps the server the first speaker. QUIC DATAGRAMs
//! carry UDP relay payloads when both peers advertise support. 0-RTT
//! application data is never accepted: the stream is only opened after the
//! 1-RTT handshake finishes.

use std::{net::SocketAddr, sync::Arc};

use quinn::{
    Endpoint, ServerConfig as QuinnServerConfig, crypto::rustls::QuicServerConfig, default_runtime,
};
use rustls::ServerConfig as RustlsServerConfig;
use uk_auth::EXPORTER_LABEL;
use uk_proto::{ALPN_PROTOCOL, BoxedCarrierReader, BoxedCarrierWriter};

type QuicError = Box<dyn std::error::Error + Send + Sync>;

/// Builds a QUIC server config from a TLS 1.3 rustls config.
///
/// The rustls config must already restrict the protocol version to TLS 1.3
/// (QUIC forbids earlier versions). ALPN is pinned to `uk/1` and 0-RTT is
/// disabled so UK application data is only processed after the full handshake.
pub fn server_config(
    mut rustls_config: RustlsServerConfig,
) -> Result<QuinnServerConfig, QuicError> {
    rustls_config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    rustls_config.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(rustls_config)
        .map_err(|err| format!("QUIC server crypto config rejected: {err}"))?;
    Ok(QuinnServerConfig::with_crypto(Arc::new(crypto)))
}

/// Binds a QUIC server endpoint to `addr` using the tokio runtime.
pub fn bind_endpoint(config: QuinnServerConfig, addr: SocketAddr) -> Result<Endpoint, QuicError> {
    let socket = std::net::UdpSocket::bind(addr)
        .map_err(|err| format!("failed to bind QUIC endpoint to {addr}: {err}"))?;
    let runtime =
        default_runtime().ok_or("no compatible async runtime found for the QUIC endpoint")?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )
    .map_err(|err| format!("failed to create QUIC endpoint: {err}"))?;
    Ok(endpoint)
}

/// Verifies that a completed QUIC connection negotiated the UK ALPN protocol.
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

/// Exports the UK auth channel binding from an established QUIC connection.
fn exporter(connection: &quinn::Connection) -> Result<[u8; 32], QuicError> {
    let mut out = [0_u8; 32];
    connection
        .export_keying_material(&mut out, EXPORTER_LABEL, &[])
        .map_err(|err| format!("QUIC keying-material export failed: {err:?}"))?;
    Ok(out)
}

/// Opens the control stream on an ALPN-verified QUIC connection and returns
/// carrier-neutral channel halves plus the auth exporter binding. The caller
/// must write to the returned writer (the server sends `AUTH_CHALLENGE` first)
/// so the stream becomes visible to the client.
pub async fn accept_carrier(
    connection: &quinn::Connection,
) -> Result<(BoxedCarrierReader, BoxedCarrierWriter, [u8; 32]), QuicError> {
    verify_alpn(connection)?;
    let exporter = exporter(connection)?;
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("failed to open QUIC control stream: {err}"))?;
    Ok((Box::new(recv), Box::new(send), exporter))
}
