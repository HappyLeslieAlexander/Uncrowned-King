//! QUIC carrier connector for the client.
//!
//! Dials a UK server over QUIC using the shared rustls TLS 1.3 material and
//! `uk/1` ALPN, then hands the server-opened control stream to the
//! carrier-neutral authentication path. The connector resolves the endpoint to
//! a socket address itself (quinn dials socket addresses, not host names) while
//! still presenting the configured server name for certificate verification.

use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, crypto::rustls::QuicClientConfig, default_runtime,
};
use rustls::ClientConfig as RustlsClientConfig;
use tokio::net::lookup_host;
use uk_auth::EXPORTER_LABEL;
use uk_proto::{
    ALPN_PROTOCOL, BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, DatagramChannel,
    DatagramSendOutcome,
};

type QuicError = Box<dyn std::error::Error + Send + Sync>;

/// Client QUIC transport keep-alive interval (15s).
///
/// Keeps NAT bindings, edge firewalls, and QUIC connection state active.
pub const DEFAULT_CLIENT_QUIC_KEEP_ALIVE: Duration = Duration::from_secs(15);

/// Client QUIC transport maximum idle timeout (60s).
///
/// Under RFC 9000 §10.1, the effective idle timeout is min(client, server).
/// Setting this to 60s avoids quinn's default 30s timeout while allowing
/// the server's setting (default 300s) to govern, or cleanly detecting
/// dead paths in 60s.
pub const DEFAULT_CLIENT_QUIC_MAX_IDLE: Duration = Duration::from_secs(60);

/// Stream receive window for QUIC client control stream (1 MiB).
pub const CLIENT_QUIC_STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;

/// Connection receive window for QUIC client connection (1 MiB).
pub const CLIENT_QUIC_CONNECTION_RECEIVE_WINDOW: u32 = 1024 * 1024;

/// Datagram receive buffer size for QUIC client UDP datagram relay (256 KiB).
pub const CLIENT_QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 256 * 1024;

/// Floor for one address's share of the endpoint handshake budget when the
/// endpoint resolves to several addresses (see
/// `per_address_attempt_timeout`).
const MIN_QUIC_PER_ADDRESS_ATTEMPT: Duration = Duration::from_secs(1);

/// Optional overrides for QUIC transport keep-alive and idle timeout.
#[derive(Clone, Debug)]
pub struct QuicTransportOverrides {
    /// Keep-alive packet interval. `None` disables transport keep-alives.
    pub keep_alive: Option<Duration>,
    /// Maximum idle timeout before declaring path failure.
    pub max_idle: Duration,
    /// When set, the endpoint socket is wrapped in the transport masking
    /// layer under these per-credential keys and MTU discovery is capped for
    /// the masking overhead.
    pub mask_keys: Option<std::sync::Arc<uk_mask::MaskKeys>>,
}

impl Default for QuicTransportOverrides {
    fn default() -> Self {
        Self {
            mask_keys: None,
            keep_alive: Some(DEFAULT_CLIENT_QUIC_KEEP_ALIVE),
            max_idle: DEFAULT_CLIENT_QUIC_MAX_IDLE,
        }
    }
}

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
    let quinn_client_config = client_config(rustls_config)?;
    connect_with_client_config(quinn_client_config, endpoint, server_name, None, None).await
}

/// Connects to `endpoint` over QUIC with optional transport parameter overrides.
///
/// `attempt_budget` is the endpoint-level handshake deadline; it is split
/// across the resolved addresses so one unreachable address cannot starve the
/// rest (see `per_address_attempt_timeout`). `None` leaves each attempt
/// unbounded.
pub async fn connect_with_overrides(
    rustls_config: RustlsClientConfig,
    endpoint: &str,
    server_name: &str,
    overrides: Option<QuicTransportOverrides>,
    attempt_budget: Option<Duration>,
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        [u8; 32],
        BoxedDatagramChannel,
    ),
    QuicError,
> {
    let mask_keys = overrides.as_ref().and_then(|opts| opts.mask_keys.clone());
    match overrides {
        Some(opts) => {
            let quinn_client_config = client_config_with_transport_masked(
                rustls_config,
                opts.keep_alive,
                opts.max_idle,
                mask_keys.is_some(),
            )?;
            connect_with_client_config(
                quinn_client_config,
                endpoint,
                server_name,
                attempt_budget,
                mask_keys,
            )
            .await
        }
        None => {
            connect_with_client_config(
                client_config(rustls_config)?,
                endpoint,
                server_name,
                attempt_budget,
                mask_keys,
            )
            .await
        }
    }
}

/// Splits an endpoint-level handshake budget across the addresses it
/// resolved to.
///
/// The dial loop is sequential, so without a per-address bound a single
/// blackholed address (the typical dual-stack v6-before-v4 failure) consumes
/// the whole budget and the remaining addresses are never dialled — exactly
/// when the fallback is needed. Single-address endpoints keep the full
/// budget; the floor keeps a tiny split (e.g. short test budgets) from
/// preempting handshakes to live servers. The outer endpoint timeout still
/// governs the total.
fn per_address_attempt_timeout(budget: Option<Duration>, address_count: usize) -> Option<Duration> {
    let budget = budget?;
    if address_count <= 1 {
        return Some(budget);
    }
    Some(
        (budget / u32::try_from(address_count).unwrap_or(u32::MAX))
            .max(MIN_QUIC_PER_ADDRESS_ATTEMPT),
    )
}

/// Connects to `endpoint` over QUIC with a custom Quinn client configuration.
///
/// `attempt_budget` bounds the whole address loop and is split per address
/// (see `per_address_attempt_timeout`); `None` leaves attempts unbounded.
pub async fn connect_with_client_config(
    quinn_client_config: QuinnClientConfig,
    endpoint: &str,
    server_name: &str,
    attempt_budget: Option<Duration>,
    mask_keys: Option<std::sync::Arc<uk_mask::MaskKeys>>,
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
    let per_address_deadline = per_address_attempt_timeout(attempt_budget, addrs.len());

    let mut last_err = None;
    for addr in addrs {
        let mut client_endpoint = match client_endpoint(unspecified_addr(addr), mask_keys.as_ref())
        {
            Ok(endpoint) => endpoint,
            Err(err) => {
                last_err =
                    Some(format!("failed to bind local QUIC socket for {addr}: {err}").into());
                continue;
            }
        };
        client_endpoint.set_default_client_config(quinn_client_config.clone());

        let connection = match client_endpoint.connect(addr, server_name) {
            Ok(connecting) => {
                // `Duration::MAX` keeps the unbudgeted case effectively
                // deadline-free while sharing one code path.
                let deadline = per_address_deadline.unwrap_or(Duration::MAX);
                match tokio::time::timeout(deadline, connecting).await {
                    Ok(result) => match result {
                        Ok(conn) => conn,
                        Err(err) => {
                            client_endpoint.close(0u32.into(), b"");
                            last_err =
                                Some(format!("QUIC handshake with {addr} failed: {err}").into());
                            continue;
                        }
                    },
                    Err(elapsed) => {
                        client_endpoint.close(0u32.into(), b"");
                        last_err = Some(format!(
                            "QUIC handshake with {addr} exceeded per-address budget {deadline:?} ({elapsed})"
                        )
                        .into());
                        continue;
                    }
                }
            }
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

/// Builds a transport config for the QUIC client with keep-alive, idle timeout,
/// and flow control bounds.
pub fn client_transport_config(
    keep_alive: Option<Duration>,
    max_idle: Duration,
) -> Result<quinn::TransportConfig, QuicError> {
    let mut transport = quinn::TransportConfig::default();
    // The server opens exactly one bidirectional control stream; nothing else.
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    transport.stream_receive_window(quinn::VarInt::from_u32(CLIENT_QUIC_STREAM_RECEIVE_WINDOW));
    transport.receive_window(quinn::VarInt::from_u32(
        CLIENT_QUIC_CONNECTION_RECEIVE_WINDOW,
    ));
    transport.datagram_receive_buffer_size(Some(CLIENT_QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE));
    transport.keep_alive_interval(keep_alive);
    let quic_idle_timeout = quinn::IdleTimeout::try_from(max_idle)
        .map_err(|err| format!("invalid QUIC client idle timeout: {err}"))?;
    transport.max_idle_timeout(Some(quic_idle_timeout));
    Ok(transport)
}

/// Builds a Quinn client config with standard production transport parameters.
pub fn client_config(rustls_config: RustlsClientConfig) -> Result<QuinnClientConfig, QuicError> {
    client_config_with_transport(
        rustls_config,
        Some(DEFAULT_CLIENT_QUIC_KEEP_ALIVE),
        DEFAULT_CLIENT_QUIC_MAX_IDLE,
    )
}

/// Builds a Quinn client config with specified keep-alive and idle timeouts.
pub fn client_config_with_transport(
    rustls_config: RustlsClientConfig,
    keep_alive: Option<Duration>,
    max_idle: Duration,
) -> Result<QuinnClientConfig, QuicError> {
    client_config_with_transport_masked(rustls_config, keep_alive, max_idle, false)
}

/// Like [`client_config_with_transport`], with masking-aware MTU discovery.
pub fn client_config_with_transport_masked(
    rustls_config: RustlsClientConfig,
    keep_alive: Option<Duration>,
    max_idle: Duration,
    masked: bool,
) -> Result<QuinnClientConfig, QuicError> {
    let crypto = QuicClientConfig::try_from(rustls_config)
        .map_err(|err| format!("QUIC client crypto config rejected: {err}"))?;
    let mut config = QuinnClientConfig::new(Arc::new(crypto));
    let mut transport = client_transport_config(keep_alive, max_idle)?;
    if masked {
        uk_mask::udp::apply_masked_mtu(&mut transport);
    }
    config.transport_config(Arc::new(transport));
    Ok(config)
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

/// Binds the client's QUIC endpoint, optionally wrapping the socket in the
/// transport masking layer under the credential's keys.
fn client_endpoint(
    addr: SocketAddr,
    mask_keys: Option<&std::sync::Arc<uk_mask::MaskKeys>>,
) -> Result<Endpoint, QuicError> {
    let Some(keys) = mask_keys else {
        return Endpoint::client(addr).map_err(QuicError::from);
    };
    let socket = std::net::UdpSocket::bind(addr)
        .map_err(|err| format!("failed to bind local QUIC socket for {addr}: {err}"))?;
    let runtime =
        default_runtime().ok_or("no compatible async runtime found for the QUIC endpoint")?;
    let wrapped = runtime
        .wrap_udp_socket(socket)
        .map_err(|err| format!("failed to wrap QUIC socket: {err}"))?;
    let masked = uk_mask::udp::MaskedUdpSocket::new_client(wrapped, keys, &mut rand::rngs::OsRng);
    Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, masked, runtime)
        .map_err(|err| format!("failed to create QUIC endpoint: {err}").into())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_config_sets_expected_defaults() {
        let transport = client_transport_config(
            Some(DEFAULT_CLIENT_QUIC_KEEP_ALIVE),
            DEFAULT_CLIENT_QUIC_MAX_IDLE,
        )
        .expect("valid default transport config");
        let debug = format!("{transport:?}");
        assert!(debug.contains("max_idle_timeout"));
        assert!(debug.contains("keep_alive_interval"));
    }

    #[test]
    fn transport_config_rejects_overflow_idle() {
        let too_large = Duration::from_secs(u64::MAX);
        assert!(client_transport_config(None, too_large).is_err());
    }

    #[test]
    fn transport_config_supports_custom_keep_alive() {
        let transport =
            client_transport_config(Some(Duration::from_millis(300)), Duration::from_secs(5))
                .expect("valid custom transport config");
        let debug = format!("{transport:?}");
        assert!(debug.contains("300ms") || debug.contains("keep_alive_interval"));
    }

    #[test]
    fn transport_config_allows_disabling_keep_alive() {
        let transport = client_transport_config(None, Duration::from_secs(5))
            .expect("valid transport config without keep alive");
        let debug = format!("{transport:?}");
        assert!(debug.contains("keep_alive_interval: None"));
    }

    #[test]
    fn per_address_budget_splits_across_addresses_with_floor() {
        // Single address keeps the whole endpoint budget.
        assert_eq!(
            per_address_attempt_timeout(Some(Duration::from_secs(10)), 1),
            Some(Duration::from_secs(10))
        );
        // Two addresses split the budget so a blackholed first address leaves
        // room for the second within the same overall deadline.
        assert_eq!(
            per_address_attempt_timeout(Some(Duration::from_secs(10)), 2),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            per_address_attempt_timeout(Some(Duration::from_secs(10)), 4),
            Some(Duration::from_millis(2500))
        );
        // Tiny budgets clamp to the floor rather than preempting live
        // handshakes; the outer endpoint timeout still bounds the total.
        assert_eq!(
            per_address_attempt_timeout(Some(Duration::from_millis(300)), 3),
            Some(MIN_QUIC_PER_ADDRESS_ATTEMPT)
        );
        // No endpoint budget: per-address attempts stay unbounded.
        assert_eq!(per_address_attempt_timeout(None, 4), None);
    }
}
