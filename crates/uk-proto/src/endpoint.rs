//! Shared host:port endpoint validation.

use std::{error::Error, fmt, net::SocketAddr};

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
        }
    }
}

impl Error for EndpointError {}

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
}
