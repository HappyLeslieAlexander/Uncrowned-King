//! Shared host:port endpoint validation.

use std::{
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
};

/// Error returned when a configured endpoint is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointError {
    name: &'static str,
    kind: EndpointErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointErrorKind {
    MissingPort,
    InvalidHost,
    InvalidPort,
    ZeroPort,
    WildcardBind,
}

impl EndpointError {
    const fn new(name: &'static str, kind: EndpointErrorKind) -> Self {
        Self { name, kind }
    }
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            EndpointErrorKind::MissingPort => write!(
                f,
                "{} must be a host:port endpoint; bracket IPv6 literals like [::1]:443",
                self.name
            ),
            EndpointErrorKind::InvalidHost => write!(f, "{} has an invalid host", self.name),
            EndpointErrorKind::InvalidPort => write!(f, "{} has an invalid port", self.name),
            EndpointErrorKind::ZeroPort => {
                write!(f, "{} port must be 1..=65535", self.name)
            }
            EndpointErrorKind::WildcardBind => write!(
                f,
                "{} must not bind a wildcard address (0.0.0.0 or [::]); \
                 the observability endpoint is unauthenticated, so bind \
                 127.0.0.1, [::1], or a specific internal interface address",
                self.name
            ),
        }
    }
}

impl Error for EndpointError {}

/// Error while resolving a validated observability bind to bindable
/// addresses.
#[derive(Debug)]
pub enum ObservabilityBindError {
    /// The configured value failed static validation (including wildcard
    /// rejection against the resolved addresses).
    Endpoint(EndpointError),
    /// The value could not be resolved, or resolved to no addresses.
    Resolve(std::io::Error),
}

impl fmt::Display for ObservabilityBindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(err) => write!(f, "{err}"),
            Self::Resolve(err) => write!(f, "resolving observability bind failed: {err}"),
        }
    }
}

impl Error for ObservabilityBindError {}

impl From<EndpointError> for ObservabilityBindError {
    fn from(err: EndpointError) -> Self {
        Self::Endpoint(err)
    }
}

/// Resolves an observability bind that already passed
/// [`validate_observability_bind`] into concrete socket addresses, failing
/// closed if any resolved address is a wildcard.
///
/// The static validator only sees the configured string, but the eventual
/// bind re-parses it through `getaddrinfo`, whose `inet_aton` semantics
/// accept numeric forms Rust's strict parser rejects (`"0"`,
/// `"000.000.000.000"`, `"0x7f.0.0.1"`). Those pass validation with only a
/// non-loopback warning yet bind `0.0.0.0` — exposing the unauthenticated
/// metrics endpoint on every interface. Binding the resolved (and here
/// re-checked) addresses instead of the raw string closes that gap: a
/// wildcard can only reach the socket if a resolver actually produced it,
/// and this is where that is caught.
pub fn resolve_observability_bind(
    name: &'static str,
    value: &str,
) -> Result<Vec<SocketAddr>, ObservabilityBindError> {
    validate_observability_bind(name, value)?;
    let addrs: Vec<SocketAddr> = value
        .to_socket_addrs()
        .map_err(ObservabilityBindError::Resolve)?
        .collect();
    if addrs.is_empty() {
        return Err(ObservabilityBindError::Resolve(std::io::Error::other(
            format!("{name} resolved to no addresses"),
        )));
    }
    if addrs
        .iter()
        .any(|addr| addr.ip().to_canonical().is_unspecified())
    {
        return Err(ObservabilityBindError::Endpoint(EndpointError::new(
            name,
            EndpointErrorKind::WildcardBind,
        )));
    }
    Ok(addrs)
}

/// Validates a `host:port` endpoint without resolving DNS.
pub fn validate_host_port_endpoint(name: &'static str, value: &str) -> Result<(), EndpointError> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return validate_port(name, addr.port());
    }

    let (host, port) = split_host_port(value)
        .ok_or_else(|| EndpointError::new(name, EndpointErrorKind::MissingPort))?;
    if host.is_empty() || host.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(EndpointError::new(name, EndpointErrorKind::InvalidHost));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| EndpointError::new(name, EndpointErrorKind::InvalidPort))?;
    validate_port(name, port)
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        Some((host, port))
    } else {
        let (host, port) = value.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        Some((host, port))
    }
}

fn validate_port(name: &'static str, port: u16) -> Result<(), EndpointError> {
    if port == 0 {
        Err(EndpointError::new(name, EndpointErrorKind::ZeroPort))
    } else {
        Ok(())
    }
}

/// How exposed an observability/metrics bind address is.
///
/// The probe endpoint served on `observability_listen` is unauthenticated,
/// so binding it anywhere reachable off-host is a deployment decision the
/// operator must make consciously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindExposure {
    /// Loopback address (`127.0.0.1`, `[::1]`): safe, no warning.
    Loopback,
    /// A specific non-loopback IP, or a hostname that cannot be classified
    /// without resolving DNS: reachable off-host, the operator must ensure
    /// it stays on an internal network.
    NonLoopback,
}

/// Validates an `observability_listen`-style bind address.
///
/// The address must first be a well-formed `host:port` endpoint
/// ([`validate_host_port_endpoint`]). Wildcard binds (`0.0.0.0`, `[::]`)
/// are rejected outright: on a host with a public address they would expose
/// the unauthenticated metrics endpoint to the internet, and a wildcard
/// never expresses the intent "internal only". Bind `127.0.0.1`, `[::1]`,
/// or a specific internal interface address (for example a Kubernetes pod
/// IP supplied via the downward API) instead.
///
/// Returns [`BindExposure::NonLoopback`] for specific non-loopback
/// addresses and hostnames so the caller can log a warning; loopback
/// binds are silent.
pub fn validate_observability_bind(
    name: &'static str,
    value: &str,
) -> Result<BindExposure, EndpointError> {
    validate_host_port_endpoint(name, value)?;
    let host = endpoint_host(value)
        .ok_or_else(|| EndpointError::new(name, EndpointErrorKind::InvalidHost))?;
    let exposure = match host.parse::<IpAddr>() {
        Ok(ip) => {
            let ip = ip.to_canonical();
            if ip.is_unspecified() {
                return Err(EndpointError::new(name, EndpointErrorKind::WildcardBind));
            }
            if ip.is_loopback() {
                BindExposure::Loopback
            } else {
                BindExposure::NonLoopback
            }
        }
        _ => BindExposure::NonLoopback,
    };
    Ok(exposure)
}

/// Extracts the host part of a `host:port` endpoint previously accepted by
/// [`validate_host_port_endpoint`].
fn endpoint_host(value: &str) -> Option<&str> {
    split_host_port(value).map(|(host, _)| host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_endpoint() {
        assert!(validate_host_port_endpoint("server_addr", "uk.example.com:443").is_ok());
    }

    #[test]
    fn accepts_socket_addr_endpoint() {
        assert!(validate_host_port_endpoint("server_addr", "127.0.0.1:443").is_ok());
    }

    #[test]
    fn accepts_bracketed_ipv6_endpoint() {
        assert!(validate_host_port_endpoint("listen", "[::1]:9443").is_ok());
    }

    #[test]
    fn rejects_endpoint_without_port() {
        assert_eq!(
            validate_host_port_endpoint("server_addr", "uk.example.com"),
            Err(EndpointError::new(
                "server_addr",
                EndpointErrorKind::MissingPort
            ))
        );
    }

    #[test]
    fn rejects_unbracketed_ipv6_endpoint() {
        assert_eq!(
            validate_host_port_endpoint("listen", "::1:9443"),
            Err(EndpointError::new("listen", EndpointErrorKind::MissingPort))
        );
    }

    #[test]
    fn rejects_empty_endpoint_host() {
        assert_eq!(
            validate_host_port_endpoint("listen", ":9443"),
            Err(EndpointError::new("listen", EndpointErrorKind::InvalidHost))
        );
    }

    #[test]
    fn rejects_control_character_in_endpoint_host() {
        assert_eq!(
            validate_host_port_endpoint("listen", "bad\nhost:9443"),
            Err(EndpointError::new("listen", EndpointErrorKind::InvalidHost))
        );
    }

    #[test]
    fn rejects_invalid_endpoint_port() {
        assert_eq!(
            validate_host_port_endpoint("listen", "127.0.0.1:https"),
            Err(EndpointError::new("listen", EndpointErrorKind::InvalidPort))
        );
    }

    #[test]
    fn rejects_zero_endpoint_port() {
        assert_eq!(
            validate_host_port_endpoint("listen", "127.0.0.1:0"),
            Err(EndpointError::new("listen", EndpointErrorKind::ZeroPort))
        );
    }

    #[test]
    fn observability_bind_accepts_loopback() {
        assert_eq!(
            validate_observability_bind("observability_listen", "127.0.0.1:9090"),
            Ok(BindExposure::Loopback)
        );
        assert_eq!(
            validate_observability_bind("observability_listen", "[::1]:9090"),
            Ok(BindExposure::Loopback)
        );
        assert_eq!(
            validate_observability_bind("observability_listen", "[::ffff:127.0.0.1]:9090"),
            Ok(BindExposure::Loopback)
        );
    }

    #[test]
    fn observability_bind_rejects_wildcard() {
        assert_eq!(
            validate_observability_bind("observability_listen", "0.0.0.0:9090"),
            Err(EndpointError::new(
                "observability_listen",
                EndpointErrorKind::WildcardBind
            ))
        );
        assert_eq!(
            validate_observability_bind("observability_listen", "[::]:9090"),
            Err(EndpointError::new(
                "observability_listen",
                EndpointErrorKind::WildcardBind
            ))
        );
        assert_eq!(
            validate_observability_bind("observability_listen", "[::ffff:0.0.0.0]:9090"),
            Err(EndpointError::new(
                "observability_listen",
                EndpointErrorKind::WildcardBind
            ))
        );
    }

    #[test]
    fn observability_bind_flags_non_loopback() {
        assert_eq!(
            validate_observability_bind("observability_listen", "10.0.0.5:9090"),
            Ok(BindExposure::NonLoopback)
        );
        // Hostnames cannot be classified without DNS; treat as non-loopback
        // so the caller warns.
        assert_eq!(
            validate_observability_bind("observability_listen", "metrics.internal:9090"),
            Ok(BindExposure::NonLoopback)
        );
    }

    #[test]
    fn resolve_bind_accepts_specific_loopback() {
        let addrs = resolve_observability_bind("observability_listen", "127.0.0.1:9090")
            .expect("loopback literal resolves");
        assert!(!addrs.is_empty());
        assert!(
            addrs
                .iter()
                .all(|addr| addr.ip().to_canonical().is_loopback())
        );
        assert!(addrs.iter().all(|addr| addr.port() == 9090));
    }

    #[test]
    fn resolve_bind_still_rejects_static_wildcard() {
        assert!(matches!(
            resolve_observability_bind("observability_listen", "0.0.0.0:9090"),
            Err(ObservabilityBindError::Endpoint(_))
        ));
    }

    /// POSIX resolvers interpret the single-label numeric host `"0"` as
    /// `0.0.0.0`, which the strict static validator cannot see.
    #[cfg(unix)]
    #[test]
    fn resolve_bind_rejects_numeric_form_that_resolves_to_wildcard() {
        assert!(matches!(
            resolve_observability_bind("observability_listen", "0:9090"),
            Err(ObservabilityBindError::Endpoint(EndpointError {
                kind: EndpointErrorKind::WildcardBind,
                ..
            }))
        ));
    }

    #[test]
    fn resolve_bind_rejects_values_that_do_not_resolve() {
        // A syntactically valid hostname that does not exist must fail closed
        // rather than bind something unexpected.
        assert!(matches!(
            resolve_observability_bind(
                "observability_listen",
                "definitely-not-a-host.invalid:9090"
            ),
            Err(ObservabilityBindError::Resolve(_))
        ));
    }
}
