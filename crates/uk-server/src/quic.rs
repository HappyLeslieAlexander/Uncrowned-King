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

use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use quinn::{
    Endpoint, ServerConfig as QuinnServerConfig, crypto::rustls::QuicServerConfig, default_runtime,
};
use rustls::ServerConfig as RustlsServerConfig;
use uk_auth::EXPORTER_LABEL;
use uk_proto::{
    ALPN_PROTOCOL, BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, DatagramChannel,
    DatagramSendOutcome,
};

type QuicError = Box<dyn std::error::Error + Send + Sync>;

/// A [`DatagramChannel`] backed by a QUIC connection, used for UDP relay over
/// QUIC DATAGRAM.
struct QuicDatagramChannel {
    connection: quinn::Connection,
}

impl DatagramChannel for QuicDatagramChannel {
    fn send(&self, datagram: Bytes) -> DatagramSendOutcome {
        match self.connection.send_datagram(datagram) {
            Ok(()) => DatagramSendOutcome::Sent,
            Err(quinn::SendDatagramError::TooLarge) => DatagramSendOutcome::TooLarge,
            Err(_) => DatagramSendOutcome::Unavailable,
        }
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = io::Result<Bytes>> + Send + '_>> {
        Box::pin(async move {
            self.connection
                .read_datagram()
                .await
                .map_err(io::Error::other)
        })
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }
}

/// Builds a shared datagram channel for an established QUIC connection.
fn datagram_channel(connection: &quinn::Connection) -> BoxedDatagramChannel {
    Arc::new(QuicDatagramChannel {
        connection: connection.clone(),
    })
}

/// Default maximum stream receive window for QUIC control streams (1 MiB).
pub const DEFAULT_QUIC_STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;
/// Default maximum connection receive window for QUIC connections (1 MiB).
pub const DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW: u32 = 1024 * 1024;
/// Minimum allowed QUIC receive window (64 KiB).
pub const MIN_QUIC_RECEIVE_WINDOW: u32 = 64 * 1024;
/// Maximum allowed QUIC receive window (16 MiB).
pub const MAX_QUIC_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;

/// Maximum stream receive window for QUIC control streams (1 MiB).
pub const QUIC_STREAM_RECEIVE_WINDOW: u32 = DEFAULT_QUIC_STREAM_RECEIVE_WINDOW;
/// Maximum connection receive window for QUIC connections (1 MiB).
pub const QUIC_CONNECTION_RECEIVE_WINDOW: u32 = DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW;
/// Datagram receive buffer size for QUIC UDP datagram relay (256 KiB).
pub const QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 256 * 1024;

/// Builds a QUIC server config from a TLS 1.3 rustls config without idle timeout.
pub fn server_config(rustls_config: RustlsServerConfig) -> Result<QuinnServerConfig, QuicError> {
    server_config_with_transport_params(
        rustls_config,
        None,
        DEFAULT_QUIC_STREAM_RECEIVE_WINDOW,
        DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW,
    )
}

/// Builds a QUIC server config from a TLS 1.3 rustls config and sets the transport
/// idle timeout.
///
/// The rustls config must already restrict the protocol version to TLS 1.3
/// (QUIC forbids earlier versions). ALPN is pinned to `uk/1` and 0-RTT is
/// disabled so UK application data is only processed after the full handshake.
/// Transport limits prevent unauthenticated peers from allocating arbitrary streams.
pub fn server_config_with_idle_timeout(
    rustls_config: RustlsServerConfig,
    idle_timeout: Option<Duration>,
) -> Result<QuinnServerConfig, QuicError> {
    server_config_with_transport_params(
        rustls_config,
        idle_timeout,
        DEFAULT_QUIC_STREAM_RECEIVE_WINDOW,
        DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW,
    )
}

/// Builds a QUIC server config from a TLS 1.3 rustls config and sets transport
/// idle timeout and receive window parameters.
pub fn server_config_with_transport_params(
    mut rustls_config: RustlsServerConfig,
    idle_timeout: Option<Duration>,
    stream_receive_window: u32,
    connection_receive_window: u32,
) -> Result<QuinnServerConfig, QuicError> {
    rustls_config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    rustls_config.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(rustls_config)
        .map_err(|err| format!("QUIC server crypto config rejected: {err}"))?;
    let mut config = QuinnServerConfig::with_crypto(Arc::new(crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(0));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    transport.stream_receive_window(quinn::VarInt::from_u32(stream_receive_window));
    transport.receive_window(quinn::VarInt::from_u32(connection_receive_window));
    transport.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE));
    let quic_idle_timeout = idle_timeout
        .map(quinn::IdleTimeout::try_from)
        .transpose()
        .map_err(|err| format!("invalid QUIC idle timeout: {err}"))?;
    transport.max_idle_timeout(quic_idle_timeout);
    config.transport_config(Arc::new(transport));

    Ok(config)
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
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        [u8; 32],
        BoxedDatagramChannel,
    ),
    QuicError,
> {
    verify_alpn(connection)?;
    let exporter = exporter(connection)?;
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("failed to open QUIC control stream: {err}"))?;
    let datagrams = datagram_channel(connection);
    Ok((Box::new(recv), Box::new(send), exporter, datagrams))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_sets_bounded_transport_parameters() {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        let quic_config = server_config(config).expect("QUIC server config should succeed");
        let debug_repr = format!("{quic_config:?}");
        assert!(
            debug_repr.contains("max_concurrent_bidi_streams: 0"),
            "bidi streams must be bounded to 0 to prevent unauthorized peer streams"
        );
        assert!(
            debug_repr.contains("max_concurrent_uni_streams: 0"),
            "uni streams must be bounded to 0 to prevent unauthorized peer streams"
        );
        assert!(
            debug_repr.contains(&format!(
                "stream_receive_window: {QUIC_STREAM_RECEIVE_WINDOW}"
            )),
            "stream receive window must match bounded parameter"
        );
        assert!(
            debug_repr.contains(&format!("receive_window: {QUIC_CONNECTION_RECEIVE_WINDOW}")),
            "connection receive window must match bounded parameter"
        );
        assert!(
            debug_repr.contains(&format!(
                "datagram_receive_buffer_size: Some({QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE})"
            )),
            "datagram receive buffer size must match bounded parameter"
        );
        assert_eq!(QUIC_STREAM_RECEIVE_WINDOW, 1024 * 1024);
        assert_eq!(QUIC_CONNECTION_RECEIVE_WINDOW, 1024 * 1024);
        assert_eq!(QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE, 256 * 1024);
        drop(quic_config);
    }

    #[test]
    fn server_config_sets_idle_timeout() {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        let quic_config =
            server_config_with_idle_timeout(config.clone(), Some(Duration::from_secs(300)))
                .expect("QUIC server config with idle timeout should succeed");
        let debug_repr = format!("{quic_config:?}");
        assert!(
            debug_repr.contains("max_idle_timeout: Some(300000)"),
            "max_idle_timeout must be configured to 300s (300000ms)"
        );

        let quic_config_none = server_config_with_idle_timeout(config.clone(), None)
            .expect("QUIC server config without idle timeout should succeed");
        let debug_repr_none = format!("{quic_config_none:?}");
        assert!(
            debug_repr_none.contains("max_idle_timeout: None"),
            "max_idle_timeout must be None when idle timeout is disabled"
        );

        let custom_quic = server_config_with_transport_params(
            config,
            Some(Duration::from_secs(60)),
            2 * 1024 * 1024,
            4 * 1024 * 1024,
        )
        .expect("QUIC server config with custom transport params should succeed");
        let custom_debug = format!("{custom_quic:?}");
        assert!(
            custom_debug.contains("stream_receive_window: 2097152"),
            "custom stream receive window must be 2 MiB"
        );
        assert!(
            custom_debug.contains("receive_window: 4194304"),
            "custom connection receive window must be 4 MiB"
        );
    }
}
