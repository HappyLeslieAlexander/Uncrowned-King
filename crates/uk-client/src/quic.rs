//! QUIC carrier connector for the client.
//!
//! Dials a UK server over QUIC using the shared rustls TLS 1.3 material and
//! `uk/1` ALPN, then hands the server-opened control stream to the
//! carrier-neutral authentication path. The connector resolves the endpoint to
//! a socket address itself (quinn dials socket addresses, not host names) while
//! still presenting the configured server name for certificate verification.

use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use bytes::Bytes;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsClientConfig;
use tokio::net::lookup_host;
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

fn datagram_channel(connection: &quinn::Connection) -> BoxedDatagramChannel {
    Arc::new(QuicDatagramChannel {
        connection: connection.clone(),
    })
}

/// Connects to `endpoint` over QUIC, verifies the UK ALPN, and returns the
/// server-opened control stream as carrier-neutral halves plus the exporter.
pub async fn connect(
    rustls_config: RustlsClientConfig,
    endpoint: &str,
    server_name: &str,
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        [u8; 32],
        BoxedDatagramChannel,
    ),
    QuicError,
> {
    let addrs = resolve(endpoint).await?;
    let quinn_client_config = client_config(rustls_config)?;

    let mut last_err = None;
    for addr in addrs {
        let mut client_endpoint = match Endpoint::client(unspecified_addr(addr)) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                last_err =
                    Some(format!("failed to bind local QUIC socket for {addr}: {err}").into());
                continue;
            }
        };
        client_endpoint.set_default_client_config(quinn_client_config.clone());

        let connection = match client_endpoint.connect(addr, server_name) {
            Ok(connecting) => match connecting.await {
                Ok(conn) => conn,
                Err(err) => {
                    client_endpoint.close(0u32.into(), b"");
                    last_err = Some(format!("QUIC handshake with {addr} failed: {err}").into());
                    continue;
                }
            },
            Err(err) => {
                client_endpoint.close(0u32.into(), b"");
                last_err = Some(format!("failed to start QUIC connection to {addr}: {err}").into());
                continue;
            }
        };

        if let Err(err) = verify_alpn(&connection) {
            connection.close(0u32.into(), b"");
            client_endpoint.close(0u32.into(), b"");
            last_err = Some(err);
            continue;
        }
        let exporter = match exporter(&connection) {
            Ok(exp) => exp,
            Err(err) => {
                connection.close(0u32.into(), b"");
                client_endpoint.close(0u32.into(), b"");
                last_err = Some(err);
                continue;
            }
        };

        let (send, recv) = match connection.accept_bi().await {
            Ok(bi) => bi,
            Err(err) => {
                connection.close(0u32.into(), b"");
                client_endpoint.close(0u32.into(), b"");
                last_err =
                    Some(format!("failed to accept QUIC control stream from {addr}: {err}").into());
                continue;
            }
        };
        let datagrams = datagram_channel(&connection);
        // Hold the connection open for the session lifetime by leaking it into the
        // endpoint's driver; the send/recv halves keep the connection state alive,
        // and the endpoint is kept alive by the spawned driver task.
        keep_endpoint_alive(client_endpoint);
        return Ok((Box::new(recv), Box::new(send), exporter, datagrams));
    }

    Err(last_err.unwrap_or_else(|| format!("failed to connect to QUIC endpoint {endpoint}").into()))
}

fn client_config(rustls_config: RustlsClientConfig) -> Result<QuinnClientConfig, QuicError> {
    let crypto = QuicClientConfig::try_from(rustls_config)
        .map_err(|err| format!("QUIC client crypto config rejected: {err}"))?;
    Ok(QuinnClientConfig::new(Arc::new(crypto)))
}

async fn resolve(endpoint: &str) -> Result<Vec<SocketAddr>, QuicError> {
    let addrs: Vec<SocketAddr> = lookup_host(endpoint)
        .await
        .map_err(|err| format!("failed to resolve QUIC endpoint {endpoint}: {err}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("QUIC endpoint {endpoint} resolved to no addresses").into());
    }
    Ok(addrs)
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
/// halves hold the connection state, so we retain the endpoint driver until
/// all connections on it have completed and gone idle.
fn keep_endpoint_alive(endpoint: Endpoint) {
    tokio::spawn(async move {
        endpoint.wait_idle().await;
    });
}
