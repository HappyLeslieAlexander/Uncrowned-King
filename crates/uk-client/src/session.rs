//! Client-side UK session setup.

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    pin::Pin,
    sync::{
        Arc, LazyLock, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use rustls::{ClientConfig as TlsClientConfig, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time,
};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};
use uk_auth::{AuthChallenge, AuthResponse, unix_now};
use uk_proto::{
    BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, ErrorCode, ErrorPayload, Frame,
    FrameLimits, FrameType, MAX_FRAME_PAYLOAD_SIZE, MAX_NEGOTIATED_FLOWS, PROTOCOL_REVISION_V1_0,
    SettingKey, Settings, read_frame, validate_connection_frame, write_frame,
};

use crate::{
    config::{CarrierKind, ClientConfig},
    tls,
};

type AnyError = Box<dyn Error + Send + Sync>;

/// A live, authenticated client carrier presented as a single duplex stream.
///
/// Wraps carrier-neutral boxed channel halves so the relay layer and tests can
/// treat every carrier (TLS/TCP, QUIC) as one `AsyncRead + AsyncWrite` value
/// and split it with [`tokio::io::split`].
pub struct ClientCarrier {
    reader: BoxedCarrierReader,
    writer: BoxedCarrierWriter,
    datagrams: Option<BoxedDatagramChannel>,
}

impl ClientCarrier {
    fn new(
        reader: BoxedCarrierReader,
        writer: BoxedCarrierWriter,
        datagrams: Option<BoxedDatagramChannel>,
    ) -> Self {
        Self {
            reader,
            writer,
            datagrams,
        }
    }

    /// Splits the carrier into its reliable channel halves and optional
    /// datagram channel for the relay to drive.
    pub(crate) fn into_parts(
        self,
    ) -> (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        Option<BoxedDatagramChannel>,
    ) {
        (self.reader, self.writer, self.datagrams)
    }
}

impl AsyncRead for ClientCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.writer).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAttemptOutcome {
    Succeeded,
    Failed(EndpointFailurePhase),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointFailurePhase {
    Tcp,
    Tls,
    Auth,
    Settings,
    Timeout,
    Protocol,
    Other,
}

impl EndpointFailurePhase {
    pub(crate) const ALL: [Self; 7] = [
        Self::Tcp,
        Self::Tls,
        Self::Auth,
        Self::Settings,
        Self::Timeout,
        Self::Protocol,
        Self::Other,
    ];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Tls => 1,
            Self::Auth => 2,
            Self::Settings => 3,
            Self::Timeout => 4,
            Self::Protocol => 5,
            Self::Other => 6,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Auth => "auth",
            Self::Settings => "settings",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
            Self::Other => "other",
        }
    }
}

#[derive(Debug)]
struct EndpointAttemptError {
    index: usize,
    endpoint: String,
    error: AnyError,
}

#[derive(Debug)]
struct ConnectAttemptsError {
    attempts: Vec<EndpointAttemptError>,
    /// Set when the endpoint loop stopped early because the server definitively
    /// rejected the configured credentials, so the remaining endpoints were
    /// never dialled.
    credential_rejection: bool,
}

impl fmt::Display for ConnectAttemptsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.attempts.is_empty() {
            return formatter.write_str("no server endpoints configured");
        }

        write!(
            formatter,
            "failed to establish authenticated UK session after {} endpoint attempt(s)",
            self.attempts.len()
        )?;
        for attempt in &self.attempts {
            write!(
                formatter,
                "; [{}] {}: {}",
                attempt.index, attempt.endpoint, attempt.error
            )?;
        }
        if self.credential_rejection {
            formatter.write_str(
                "; the server rejected these credentials, so the remaining endpoints were not tried",
            )?;
        }
        Ok(())
    }
}

impl Error for ConnectAttemptsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.attempts
            .last()
            .map(|attempt| attempt.error.as_ref() as &(dyn Error + 'static))
    }
}

#[derive(Debug)]
struct HandshakePhaseError {
    phase: &'static str,
    failure_phase: EndpointFailurePhase,
    source: AnyError,
}

#[derive(Debug)]
struct ServerHandshakeError {
    code: ErrorCode,
}

impl fmt::Display for HandshakePhaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed: {}", self.phase, self.source)
    }
}

impl Error for HandshakePhaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl fmt::Display for ServerHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            ErrorCode::AuthFailed => formatter.write_str("authentication failed"),
            code => write!(formatter, "server returned handshake error: {code:?}"),
        }
    }
}

impl Error for ServerHandshakeError {}

/// Connects to the configured server and completes UK authentication.
pub async fn connect_authenticated(
    config: &ClientConfig,
) -> Result<(ClientCarrier, Settings), AnyError> {
    connect_authenticated_observed(config, |_| {}).await
}

/// Connects to the configured server and completes UK authentication with
/// optional QUIC transport parameter overrides.
pub async fn connect_authenticated_with_quic_overrides(
    config: &ClientConfig,
    overrides: Option<crate::quic::QuicTransportOverrides>,
) -> Result<(ClientCarrier, Settings), AnyError> {
    config.validate_network_endpoints()?;
    config.validate_auth_material()?;
    connect_authenticated_inner_with_overrides(
        config,
        handshake_timeout(config.handshake_timeout_seconds()),
        overrides,
        |_| {},
    )
    .await
}

pub(crate) async fn connect_authenticated_observed<F>(
    config: &ClientConfig,
    observe: F,
) -> Result<(ClientCarrier, Settings), AnyError>
where
    F: FnMut(EndpointAttemptOutcome),
{
    config.validate_network_endpoints()?;
    config.validate_auth_material()?;
    connect_authenticated_inner(
        config,
        handshake_timeout(config.handshake_timeout_seconds()),
        observe,
    )
    .await
}

/// `(cooldown deadline, config epoch that recorded the penalty)`.
type DegradedEndpointEntry = (Instant, u64);

static DEGRADED_ENDPOINTS: LazyLock<StdMutex<HashMap<String, DegradedEndpointEntry>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));
static DEGRADED_EPOCH: AtomicU64 = AtomicU64::new(0);
const DEGRADED_COOLDOWN: Duration = Duration::from_secs(180);

fn degraded_epoch() -> u64 {
    DEGRADED_EPOCH.load(Ordering::Acquire)
}

fn is_endpoint_degraded(endpoint: &str, epoch: u64) -> bool {
    let Ok(mut map) = DEGRADED_ENDPOINTS.lock() else {
        return false;
    };
    let now = Instant::now();
    map.retain(|_, (until, _)| *until > now);
    // Penalties belong to the config generation that observed the failure:
    // after a reload, an old-generation connect still in flight must not
    // impose its 180s cooldown on the new configuration's endpoints.
    map.get(endpoint)
        .is_some_and(|(_, marked_epoch)| *marked_epoch == epoch)
}

fn mark_endpoint_degraded(endpoint: &str, epoch: u64) {
    if let Ok(mut map) = DEGRADED_ENDPOINTS.lock() {
        map.insert(
            endpoint.to_owned(),
            (Instant::now() + DEGRADED_COOLDOWN, epoch),
        );
    }
}

fn clear_endpoint_degraded(endpoint: &str) {
    if let Ok(mut map) = DEGRADED_ENDPOINTS.lock() {
        map.remove(endpoint);
    }
}

/// Clears all degraded-endpoint cooldowns and starts a new degradation epoch.
///
/// Called when a config reload is applied: the operator just changed the
/// network posture (possibly fixing whatever degraded the endpoint), so
/// penalties recorded under the old config must not linger for up to
/// `DEGRADED_COOLDOWN` on reused endpoints — including penalties that an
/// old-generation connect writes *after* this clear.
pub(crate) fn clear_degraded_endpoints() {
    if let Ok(mut map) = DEGRADED_ENDPOINTS.lock() {
        map.clear();
        DEGRADED_EPOCH.fetch_add(1, Ordering::AcqRel);
    }
}

async fn connect_authenticated_inner<F>(
    config: &ClientConfig,
    endpoint_timeout: Option<Duration>,
    observe: F,
) -> Result<(ClientCarrier, Settings), AnyError>
where
    F: FnMut(EndpointAttemptOutcome),
{
    connect_authenticated_inner_with_overrides(config, endpoint_timeout, None, observe).await
}

async fn connect_authenticated_inner_with_overrides<F>(
    config: &ClientConfig,
    endpoint_timeout: Option<Duration>,
    overrides: Option<crate::quic::QuicTransportOverrides>,
    mut observe: F,
) -> Result<(ClientCarrier, Settings), AnyError>
where
    F: FnMut(EndpointAttemptOutcome),
{
    // Loaded once per connect, off the runtime worker, and reused by every
    // endpoint attempt below: neither the TLS/TCP nor the QUIC carrier may
    // re-read the CA bundle while dialling.
    let tls_config = tls::shared_client_config(&config.ca_cert_path).await?;
    let server_name = tls::server_name(config.server_name.clone())?;
    let mut attempts = Vec::new();
    let mut credential_rejection = false;
    let epoch = degraded_epoch();

    let raw_endpoints = config.server_endpoints();
    let mut healthy = Vec::new();
    let mut degraded = Vec::new();
    for ep in raw_endpoints {
        if is_endpoint_degraded(ep, epoch) {
            degraded.push(ep);
        } else {
            healthy.push(ep);
        }
    }
    let ordered_endpoints = if healthy.is_empty() {
        degraded
    } else {
        healthy.extend(degraded);
        healthy
    };

    for (index, endpoint) in ordered_endpoints.into_iter().enumerate() {
        match connect_authenticated_endpoint_with_timeout(
            config,
            &tls_config,
            server_name.clone(),
            endpoint,
            endpoint_timeout,
            overrides,
        )
        .await
        {
            Ok(session) => {
                clear_endpoint_degraded(endpoint);
                observe(EndpointAttemptOutcome::Succeeded);
                return Ok(session);
            }
            Err(err) => {
                let failure_phase = endpoint_failure_phase(&err);
                credential_rejection = is_credential_rejection(&err);
                let is_quic_transport_failure = matches!(
                    crate::config::parse_endpoint(endpoint),
                    Ok((CarrierKind::Quic, _))
                ) && matches!(
                    failure_phase,
                    EndpointFailurePhase::Tls
                        | EndpointFailurePhase::Tcp
                        | EndpointFailurePhase::Timeout
                );
                if (failure_phase == EndpointFailurePhase::Timeout || is_quic_transport_failure)
                    && !credential_rejection
                {
                    mark_endpoint_degraded(endpoint, epoch);
                }
                observe(EndpointAttemptOutcome::Failed(failure_phase));
                warn!(
                    event = "client.session.connect_endpoint_failed",
                    attempt = index,
                    server_addr = %endpoint,
                    failure_phase = failure_phase.label(),
                    credential_rejection,
                    error = %err
                );
                attempts.push(EndpointAttemptError {
                    index,
                    endpoint: endpoint.to_owned(),
                    error: err,
                });
                if credential_rejection {
                    // The credentials, not this carrier, are what the server
                    // refused. Every remaining endpoint would replay the same
                    // full handshake only to be rejected identically, costing
                    // another `handshake_timeout` per SOCKS connection.
                    break;
                }
            }
        }
    }

    Err(Box::new(ConnectAttemptsError {
        attempts,
        credential_rejection,
    }))
}

async fn connect_authenticated_endpoint_with_timeout(
    config: &ClientConfig,
    tls_config: &Arc<TlsClientConfig>,
    server_name: ServerName<'static>,
    endpoint: &str,
    endpoint_timeout: Option<Duration>,
    overrides: Option<crate::quic::QuicTransportOverrides>,
) -> Result<(ClientCarrier, Settings), AnyError> {
    if let Some(timeout) = endpoint_timeout {
        match time::timeout(
            timeout,
            connect_authenticated_endpoint(config, tls_config, server_name, endpoint, overrides),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(phase_error(
                "client handshake",
                EndpointFailurePhase::Timeout,
                format!("deadline exceeded for {endpoint} after {timeout:?}"),
            )),
        }
    } else {
        connect_authenticated_endpoint(config, tls_config, server_name, endpoint, overrides).await
    }
}

async fn connect_authenticated_endpoint(
    config: &ClientConfig,
    tls_config: &Arc<TlsClientConfig>,
    server_name: ServerName<'static>,
    endpoint: &str,
    overrides: Option<crate::quic::QuicTransportOverrides>,
) -> Result<(ClientCarrier, Settings), AnyError> {
    let (carrier, addr) = crate::config::parse_endpoint(endpoint)
        .map_err(|err| phase_error("parse endpoint", EndpointFailurePhase::Other, err))?;
    let (reader, writer, exporter, datagrams) = match carrier {
        CarrierKind::Tls => {
            // Wrapping the shared config in a connector is a pointer copy, so
            // each attempt can have its own without re-reading the CA bundle.
            let connector = tls::connector_from(Arc::clone(tls_config));
            establish_tls_carrier(&connector, server_name, addr).await?
        }
        CarrierKind::Quic => establish_quic_carrier(config, tls_config, addr, overrides).await?,
    };
    authenticate_over_carrier(config, reader, writer, exporter, datagrams).await
}

async fn establish_tls_carrier(
    connector: &TlsConnector,
    server_name: ServerName<'static>,
    addr: &str,
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        [u8; 32],
        Option<BoxedDatagramChannel>,
    ),
    AnyError,
> {
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|err| phase_error("tcp connect", EndpointFailurePhase::Tcp, err))?;
    tcp.set_nodelay(true)
        .map_err(|err| phase_error("tcp nodelay", EndpointFailurePhase::Tcp, err))?;
    let stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|err| phase_error("tls connect", EndpointFailurePhase::Tls, err))?;
    tls::verify_alpn(&stream)
        .map_err(|err| phase_error("tls alpn verify", EndpointFailurePhase::Tls, err))?;
    let exporter = tls::exporter(&stream)
        .map_err(|err| phase_error("tls exporter", EndpointFailurePhase::Tls, err))?;
    let (reader, writer) = tokio::io::split(stream);
    // The TLS/TCP carrier has no datagram channel.
    Ok((Box::new(reader), Box::new(writer), exporter, None))
}

async fn establish_quic_carrier(
    config: &ClientConfig,
    tls_config: &Arc<TlsClientConfig>,
    addr: &str,
    overrides: Option<crate::quic::QuicTransportOverrides>,
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        [u8; 32],
        Option<BoxedDatagramChannel>,
    ),
    AnyError,
> {
    let (reader, writer, exporter, datagrams) = crate::quic::connect_with_overrides(
        tls_config.as_ref().clone(),
        addr,
        &config.server_name,
        overrides,
    )
    .await
    .map_err(|err| phase_error("quic connect", EndpointFailurePhase::Tls, err))?;
    Ok((reader, writer, exporter, Some(datagrams)))
}

/// Runs the UK challenge-response authentication over an established,
/// ALPN-verified carrier. Carrier-neutral: the TLS/TCP and QUIC connectors both
/// establish their transport and exporter binding, then delegate here.
async fn authenticate_over_carrier(
    config: &ClientConfig,
    mut reader: BoxedCarrierReader,
    mut writer: BoxedCarrierWriter,
    exporter: [u8; 32],
    datagrams: Option<BoxedDatagramChannel>,
) -> Result<(ClientCarrier, Settings), AnyError> {
    let challenge_frame = read_frame(&mut reader, FrameLimits::default())
        .await
        .map_err(|err| phase_error("read auth challenge", EndpointFailurePhase::Auth, err))?;
    validate_connection_frame(&challenge_frame, FrameType::AuthChallenge).map_err(|err| {
        phase_error(
            "validate auth challenge",
            EndpointFailurePhase::Protocol,
            err,
        )
    })?;
    let mut challenge_payload = challenge_frame.payload;
    let challenge = AuthChallenge::decode(&mut challenge_payload)
        .map_err(|err| phase_error("decode auth challenge", EndpointFailurePhase::Protocol, err))?;

    let response = AuthResponse::for_challenge(
        config.key_id.as_bytes(),
        config.secret.as_bytes(),
        &exporter,
        &challenge,
        unix_now(),
        Vec::new(),
    )
    .map_err(|err| phase_error("build auth response", EndpointFailurePhase::Auth, err))?;
    let mut response_payload = BytesMut::new();
    response
        .encode(&mut response_payload)
        .map_err(|err| phase_error("encode auth response", EndpointFailurePhase::Auth, err))?;
    let response_frame = Frame::new(FrameType::AuthResponse, 0, 0, response_payload.freeze())
        .map_err(|err| phase_error("build auth response frame", EndpointFailurePhase::Auth, err))?;
    write_frame(&mut writer, &response_frame)
        .await
        .map_err(|err| phase_error("write auth response", EndpointFailurePhase::Auth, err))?;

    let settings_frame = read_frame(&mut reader, FrameLimits::default())
        .await
        .map_err(|err| phase_error("read server settings", EndpointFailurePhase::Auth, err))?;
    let settings = decode_server_settings_frame(settings_frame)?;
    let negotiated = settings.negotiated_v1_0().map_err(|err| {
        phase_error(
            "negotiate server settings",
            EndpointFailurePhase::Settings,
            err,
        )
    })?;
    // The 1.0 contract says peers exchange SETTINGS. The server has already
    // advertised its receive limits; announce ours before entering relay so a
    // conforming peer does not wait for this frame.
    let client_settings = client_settings(config, datagrams.is_some());
    let mut client_settings_payload = BytesMut::new();
    client_settings
        .encode(&mut client_settings_payload)
        .map_err(|err| {
            phase_error(
                "encode client settings",
                EndpointFailurePhase::Settings,
                err,
            )
        })?;
    let client_settings_frame =
        Frame::new(FrameType::Settings, 0, 0, client_settings_payload.freeze()).map_err(|err| {
            phase_error(
                "build client settings frame",
                EndpointFailurePhase::Settings,
                err,
            )
        })?;
    write_frame(&mut writer, &client_settings_frame)
        .await
        .map_err(|err| phase_error("write client settings", EndpointFailurePhase::Settings, err))?;

    info!(
        event = "auth.success",
        max_frame_size = negotiated.max_frame_size
    );
    Ok((ClientCarrier::new(reader, writer, datagrams), settings))
}

fn client_settings(config: &ClientConfig, supports_udp_datagram: bool) -> Settings {
    let mut settings = Settings::default();
    settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V1_0);
    settings.set(SettingKey::MaxFrameSize, MAX_FRAME_PAYLOAD_SIZE);
    let streams = config.max_socks_connections().min(MAX_NEGOTIATED_FLOWS);
    settings.set(SettingKey::MaxStreams, streams);
    settings.set(SettingKey::MaxUdpFlows, streams);
    settings.set(
        SettingKey::SupportsUdpDatagram,
        u64::from(supports_udp_datagram),
    );
    settings.set(SettingKey::SupportsUdpStreamFallback, 1);
    // The client does not impose a protocol idle timeout on the server.
    settings.set(SettingKey::IdleTimeoutSeconds, 0);
    settings
}

fn decode_server_settings_frame(frame: Frame) -> Result<Settings, AnyError> {
    match frame.header.frame_type {
        FrameType::Settings => {
            validate_connection_frame(&frame, FrameType::Settings).map_err(|err| {
                phase_error(
                    "validate server settings",
                    EndpointFailurePhase::Protocol,
                    err,
                )
            })?;
            let mut settings_payload = frame.payload;
            let settings = Settings::decode(&mut settings_payload).map_err(|err| {
                phase_error(
                    "decode server settings",
                    EndpointFailurePhase::Protocol,
                    err,
                )
            })?;
            settings.negotiated_v1_0().map_err(|err| {
                phase_error(
                    "negotiate server settings",
                    EndpointFailurePhase::Settings,
                    err,
                )
            })?;
            Ok(settings)
        }
        FrameType::Error => {
            validate_connection_frame(&frame, FrameType::Error).map_err(|err| {
                phase_error(
                    "validate server handshake error",
                    EndpointFailurePhase::Protocol,
                    err,
                )
            })?;
            let mut payload = frame.payload;
            let status = ErrorPayload::decode(&mut payload).map_err(|err| {
                phase_error(
                    "decode server handshake error",
                    EndpointFailurePhase::Protocol,
                    err,
                )
            })?;
            Err(Box::new(ServerHandshakeError { code: status.code }))
        }
        _ => {
            validate_connection_frame(&frame, FrameType::Settings).map_err(|err| {
                phase_error(
                    "validate server response",
                    EndpointFailurePhase::Protocol,
                    err,
                )
            })?;
            Err("unexpected connection frame type".into())
        }
    }
}

fn phase_error<E>(phase: &'static str, failure_phase: EndpointFailurePhase, source: E) -> AnyError
where
    E: Into<AnyError>,
{
    Box::new(HandshakePhaseError {
        phase,
        failure_phase,
        source: source.into(),
    })
}

fn endpoint_failure_phase(error: &AnyError) -> EndpointFailurePhase {
    let mut current = Some(error.as_ref() as &(dyn Error + 'static));
    while let Some(source) = current {
        if source.downcast_ref::<ServerHandshakeError>().is_some() {
            return EndpointFailurePhase::Auth;
        }
        current = source.source();
    }

    let mut current = Some(error.as_ref() as &(dyn Error + 'static));
    while let Some(source) = current {
        if let Some(error) = source.downcast_ref::<HandshakePhaseError>() {
            return error.failure_phase;
        }
        current = source.source();
    }
    EndpointFailurePhase::Other
}

/// Reports whether the server structurally refused the configured credentials,
/// i.e. answered the `AuthResponse` with `ERROR{AuthFailed}`.
///
/// Keyed on [`ServerHandshakeError`] rather than [`EndpointFailurePhase::Auth`]
/// on purpose: that phase is also produced by plain I/O failures while reading
/// or writing the auth frames (a reset carrier, a truncated challenge), which
/// are per-endpoint problems and must still fall back to the next carrier. Only
/// a decoded rejection from the server proves the next endpoint would fail the
/// same way.
fn is_credential_rejection(error: &AnyError) -> bool {
    let mut current = Some(error.as_ref() as &(dyn Error + 'static));
    while let Some(source) = current {
        if let Some(rejection) = source.downcast_ref::<ServerHandshakeError>() {
            return matches!(rejection.code, ErrorCode::AuthFailed);
        }
        current = source.source();
    }
    false
}

fn handshake_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uk_proto::{MAX_FRAME_PAYLOAD_SIZE, MIN_TCP_RELAY_FRAME_SIZE, SettingKey};

    fn settings_frame(settings: &Settings) -> Frame {
        let mut payload = BytesMut::new();
        settings.encode(&mut payload).unwrap();
        Frame::new(FrameType::Settings, 0, 0, payload.freeze()).unwrap()
    }

    fn error_frame(code: ErrorCode) -> Frame {
        let mut payload = BytesMut::new();
        ErrorPayload::new(code).encode(&mut payload).unwrap();
        Frame::new(FrameType::Error, 0, 0, payload.freeze()).unwrap()
    }

    fn attempt_error(index: usize, endpoint: &str, error: &str) -> EndpointAttemptError {
        EndpointAttemptError {
            index,
            endpoint: endpoint.to_owned(),
            error: error.to_owned().into(),
        }
    }

    #[test]
    fn accepts_supported_protocol_revision() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);

        assert!(settings.negotiated_v1_0().is_ok());
    }

    #[test]
    fn decodes_server_settings_frame() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::MaxFrameSize, 4096);
        settings.set(SettingKey::MaxStreams, 8);

        assert_eq!(
            decode_server_settings_frame(settings_frame(&settings)).unwrap(),
            settings
        );
    }

    #[test]
    fn endpoint_attempt_error_reports_every_failure() {
        let error = ConnectAttemptsError {
            attempts: vec![
                attempt_error(0, "127.0.0.1:1", "connection refused"),
                attempt_error(1, "127.0.0.1:2", "handshake timeout"),
            ],
            credential_rejection: false,
        };
        let text = error.to_string();

        assert!(text.contains("2 endpoint attempt"));
        assert!(text.contains("[0] 127.0.0.1:1: connection refused"));
        assert!(text.contains("[1] 127.0.0.1:2: handshake timeout"));
        assert!(!text.contains("remaining endpoints were not tried"));
    }

    #[test]
    fn endpoint_attempt_error_reports_an_abandoned_endpoint_fallback() {
        let error = ConnectAttemptsError {
            attempts: vec![attempt_error(
                0,
                "quic://127.0.0.1:1",
                "authentication failed",
            )],
            credential_rejection: true,
        };
        let text = error.to_string();

        assert!(text.contains("1 endpoint attempt"));
        assert!(text.contains("[0] quic://127.0.0.1:1: authentication failed"));
        assert!(text.contains("the server rejected these credentials"));
        assert!(text.contains("remaining endpoints were not tried"));
    }

    #[test]
    fn empty_endpoint_attempt_error_reports_no_endpoints() {
        let error = ConnectAttemptsError {
            attempts: Vec::new(),
            credential_rejection: false,
        };

        assert_eq!(error.to_string(), "no server endpoints configured");
    }

    #[test]
    fn handshake_phase_error_reports_phase_and_source() {
        let error = phase_error(
            "tls connect",
            EndpointFailurePhase::Tls,
            "certificate verify failed",
        );

        assert_eq!(
            error.to_string(),
            "tls connect failed: certificate verify failed"
        );
        assert!(error.source().is_some());
        assert_eq!(endpoint_failure_phase(&error), EndpointFailurePhase::Tls);
    }

    #[test]
    fn classifies_nested_server_rejection_as_auth_failure() {
        let rejection: AnyError = Box::new(ServerHandshakeError {
            code: ErrorCode::AuthFailed,
        });
        let error = phase_error(
            "decode server settings",
            EndpointFailurePhase::Settings,
            rejection,
        );

        assert_eq!(endpoint_failure_phase(&error), EndpointFailurePhase::Auth);
    }

    #[test]
    fn classifies_unstructured_endpoint_error_as_other() {
        let error: AnyError = "unstructured failure".into();

        assert_eq!(endpoint_failure_phase(&error), EndpointFailurePhase::Other);
    }

    #[test]
    fn maps_auth_failed_error_frame() {
        let error = decode_server_settings_frame(error_frame(ErrorCode::AuthFailed)).unwrap_err();

        assert!(error.to_string().contains("authentication failed"));
        assert_eq!(endpoint_failure_phase(&error), EndpointFailurePhase::Auth);
    }

    #[test]
    fn rejects_non_auth_handshake_error_frame() {
        let error = decode_server_settings_frame(error_frame(ErrorCode::Protocol)).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("server returned handshake error")
        );
    }

    #[test]
    fn treats_server_auth_rejection_as_a_credential_rejection() {
        let error = decode_server_settings_frame(error_frame(ErrorCode::AuthFailed)).unwrap_err();

        assert!(is_credential_rejection(&error));
    }

    #[test]
    fn treats_nested_server_auth_rejection_as_a_credential_rejection() {
        let rejection: AnyError = Box::new(ServerHandshakeError {
            code: ErrorCode::AuthFailed,
        });
        let error = phase_error(
            "decode server settings",
            EndpointFailurePhase::Settings,
            rejection,
        );

        assert!(is_credential_rejection(&error));
    }

    #[test]
    fn does_not_treat_auth_phase_io_errors_as_a_credential_rejection() {
        // These are the `EndpointFailurePhase::Auth` errors that a broken
        // carrier produces; the next endpoint must still be tried.
        for phase in [
            "read auth challenge",
            "write auth response",
            "read server settings",
        ] {
            let error = phase_error(
                phase,
                EndpointFailurePhase::Auth,
                std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            );

            assert_eq!(endpoint_failure_phase(&error), EndpointFailurePhase::Auth);
            assert!(
                !is_credential_rejection(&error),
                "{phase} must stay retryable"
            );
        }
    }

    #[test]
    fn does_not_treat_other_server_handshake_errors_as_a_credential_rejection() {
        let error = decode_server_settings_frame(error_frame(ErrorCode::Protocol)).unwrap_err();

        assert!(!is_credential_rejection(&error));
    }

    #[test]
    fn rejects_missing_protocol_revision() {
        let settings = Settings::default();

        assert!(settings.negotiated_v1_0().is_err());
    }

    #[test]
    fn classifies_invalid_negotiated_settings() {
        let settings = Settings::default();

        let error = decode_server_settings_frame(settings_frame(&settings)).unwrap_err();

        assert_eq!(
            endpoint_failure_phase(&error),
            EndpointFailurePhase::Settings
        );
    }

    #[test]
    fn rejects_unsupported_protocol_revision() {
        let mut settings = Settings::default();
        // Revision 1 is the retired 0.x experimental wire format.
        settings.set(SettingKey::ProtocolRevision, 1);

        assert!(settings.negotiated_v1_0().is_err());
    }

    #[test]
    fn rejects_zero_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::MaxFrameSize, 0);

        assert!(settings.negotiated_v1_0().is_err());
    }

    #[test]
    fn rejects_too_small_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::MaxFrameSize, MIN_TCP_RELAY_FRAME_SIZE - 1);

        assert!(settings.negotiated_v1_0().is_err());
    }

    #[test]
    fn rejects_too_large_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::MaxFrameSize, MAX_FRAME_PAYLOAD_SIZE + 1);

        assert!(settings.negotiated_v1_0().is_err());
    }

    #[test]
    fn rejects_zero_max_streams() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::MaxStreams, 0);

        assert!(settings.negotiated_v1_0().is_err());
    }

    #[test]
    fn rejects_udp_flow_limit_above_stream_limit() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::MaxStreams, 8);
        settings.set(SettingKey::MaxUdpFlows, 9);

        let error = settings.negotiated_v1_0().unwrap_err();
        assert!(error.to_string().contains("max_udp_flows"));
    }

    #[test]
    fn rejects_udp_flow_limit_above_default_stream_limit() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::MaxUdpFlows, uk_proto::DEFAULT_MAX_STREAMS + 1);

        let error = settings.negotiated_v1_0().unwrap_err();
        assert!(error.to_string().contains("max_udp_flows"));
    }

    #[test]
    fn accepts_boolean_udp_support_settings() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::SupportsUdpDatagram, 0);
        settings.set(SettingKey::SupportsUdpStreamFallback, 1);

        assert!(settings.negotiated_v1_0().is_ok());
    }

    #[test]
    fn rejects_non_boolean_udp_support_settings() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);
        settings.set(SettingKey::SupportsUdpStreamFallback, 2);

        assert!(settings.negotiated_v1_0().is_err());
    }

    #[test]
    fn tracks_and_clears_degraded_endpoints() {
        clear_degraded_endpoints();
        let epoch = degraded_epoch();
        let ep = "quic://127.0.0.1:9443";
        assert!(!is_endpoint_degraded(ep, epoch));
        mark_endpoint_degraded(ep, epoch);
        assert!(is_endpoint_degraded(ep, epoch));
        clear_endpoint_degraded(ep);
        assert!(!is_endpoint_degraded(ep, epoch));
        mark_endpoint_degraded(ep, epoch);
        clear_degraded_endpoints();
        assert!(!is_endpoint_degraded(ep, epoch));
    }

    #[test]
    fn degraded_endpoints_do_not_leak_across_reload_epochs() {
        clear_degraded_endpoints();
        let old_epoch = degraded_epoch();
        let ep = "quic://127.0.0.1:9443";

        // A reload lands while an old-generation connect is still in flight...
        clear_degraded_endpoints();
        let new_epoch = degraded_epoch();
        assert_ne!(old_epoch, new_epoch);

        // ...and the old connect only reports its failure afterwards.
        mark_endpoint_degraded(ep, old_epoch);
        assert!(
            !is_endpoint_degraded(ep, new_epoch),
            "a late old-generation penalty must not degrade the new config"
        );
        // Same-epoch penalties still apply.
        mark_endpoint_degraded(ep, new_epoch);
        assert!(is_endpoint_degraded(ep, new_epoch));
        assert!(!is_endpoint_degraded(ep, new_epoch + 1));
        clear_degraded_endpoints();
    }

    #[tokio::test]
    async fn quic_transport_failure_marks_endpoint_degraded() {
        clear_degraded_endpoints();
        let path =
            std::env::temp_dir().join(format!("quic-degraded-test-ca-{}.pem", std::process::id()));
        std::fs::write(
            &path,
            include_str!("../../../docs/audits/2026-09-09/evidence/client/audit-ca-one.pem"),
        )
        .unwrap();
        let quic_ep = "quic://127.0.0.1:1";
        let config = ClientConfig {
            server_addr: quic_ep.to_owned(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: path.to_string_lossy().into_owned(),
            key_id: "client-a".to_owned(),
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            handshake_timeout_seconds: Some(1),
            server_connect_retry_delay_millis: Some(0),
            socks_handshake_timeout_seconds: None,
            tcp_open_timeout_seconds: None,
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
            relay_buffer_size: None,
        };
        // Capture the epoch the connect will run under: parallel tests bump
        // it via clear_degraded_endpoints(), which must not mask this mark.
        let connect_epoch = degraded_epoch();
        assert!(!is_endpoint_degraded(quic_ep, connect_epoch));
        let res = connect_authenticated(&config).await;
        std::fs::remove_file(&path).ok();
        assert!(res.is_err());
        assert!(
            is_endpoint_degraded(quic_ep, connect_epoch),
            "failed QUIC connection attempt must mark endpoint as degraded"
        );
        clear_degraded_endpoints();
    }
}
