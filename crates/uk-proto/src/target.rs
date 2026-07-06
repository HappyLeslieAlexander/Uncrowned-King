//! Strict target address encoding.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut};

use crate::{ProtocolError, ProtocolResult, varint};

const ADDR_DOMAIN: u8 = 0x01;
const ADDR_IPV4: u8 = 0x02;
const ADDR_IPV6: u8 = 0x03;

/// A proxy target address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    /// A domain name and port.
    Domain(String, u16),
    /// An IPv4 address and port.
    Ipv4(Ipv4Addr, u16),
    /// An IPv6 address and port.
    Ipv6(Ipv6Addr, u16),
}

impl Target {
    /// Returns the target port.
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, port) | Self::Ipv4(_, port) | Self::Ipv6(_, port) => *port,
        }
    }

    /// Returns a stable, escaped target string suitable for logs.
    pub fn log_safe(&self) -> String {
        match self {
            Self::Domain(domain, port) => format!("domain:{}:{port}", domain.escape_debug()),
            Self::Ipv4(addr, port) => format!("ipv4:{addr}:{port}"),
            Self::Ipv6(addr, port) => format!("ipv6:[{addr}]:{port}"),
        }
    }

    /// Encodes this target into `dst`.
    pub fn encode(&self, dst: &mut impl BufMut) -> ProtocolResult<()> {
        validate_port(self.port())?;
        match self {
            Self::Domain(domain, port) => {
                validate_domain(domain)?;
                dst.put_u8(ADDR_DOMAIN);
                varint::encode(domain.len() as u64, dst)?;
                dst.put_slice(domain.as_bytes());
                dst.put_u16(*port);
            }
            Self::Ipv4(addr, port) => {
                dst.put_u8(ADDR_IPV4);
                varint::encode(4, dst)?;
                dst.put_slice(&addr.octets());
                dst.put_u16(*port);
            }
            Self::Ipv6(addr, port) => {
                dst.put_u8(ADDR_IPV6);
                varint::encode(16, dst)?;
                dst.put_slice(&addr.octets());
                dst.put_u16(*port);
            }
        }
        Ok(())
    }

    /// Decodes a target from `src`.
    pub fn decode(src: &mut impl Buf) -> ProtocolResult<Self> {
        if !src.has_remaining() {
            return Err(ProtocolError::Truncated);
        }
        let addr_type = src.get_u8();
        let host_len =
            usize::try_from(varint::decode(src)?).map_err(|_| ProtocolError::InvalidVarint)?;
        if src.remaining() < host_len + 2 {
            return Err(ProtocolError::Truncated);
        }
        let host = src.copy_to_bytes(host_len);
        let port = src.get_u16();
        validate_port(port)?;

        match addr_type {
            ADDR_DOMAIN => {
                if host.is_empty() || host.len() > 255 {
                    return Err(ProtocolError::InvalidTarget("invalid domain length"));
                }
                let domain = std::str::from_utf8(&host)
                    .map_err(|_| ProtocolError::InvalidTarget("domain is not utf-8"))?;
                validate_domain(domain)?;
                Ok(Self::Domain(domain.to_owned(), port))
            }
            ADDR_IPV4 => {
                let octets: [u8; 4] = host
                    .as_ref()
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidTarget("invalid ipv4 length"))?;
                Ok(Self::Ipv4(Ipv4Addr::from(octets), port))
            }
            ADDR_IPV6 => {
                let octets: [u8; 16] = host
                    .as_ref()
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidTarget("invalid ipv6 length"))?;
                Ok(Self::Ipv6(Ipv6Addr::from(octets), port))
            }
            _ => Err(ProtocolError::InvalidTarget("unknown address type")),
        }
    }
}

fn validate_port(port: u16) -> ProtocolResult<()> {
    if port == 0 {
        Err(ProtocolError::InvalidTarget("port must be 1..=65535"))
    } else {
        Ok(())
    }
}

fn validate_domain(domain: &str) -> ProtocolResult<()> {
    if domain.is_empty() || domain.len() > 255 {
        return Err(ProtocolError::InvalidTarget("invalid domain length"));
    }
    if domain.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ProtocolError::InvalidTarget(
            "domain contains ascii control character",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn encodes_domain_vector() {
        let target = Target::Domain("example.com".to_owned(), 443);
        let mut out = Vec::new();
        target.encode(&mut out).unwrap();
        assert_eq!(
            out,
            [
                0x01, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
                0xbb
            ]
        );
    }

    #[test]
    fn encodes_ipv4_vector() {
        let target = Target::Ipv4(Ipv4Addr::LOCALHOST, 8080);
        let mut out = Vec::new();
        target.encode(&mut out).unwrap();
        assert_eq!(out, [0x02, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x1f, 0x90]);
    }

    #[test]
    fn encodes_ipv6_vector() {
        let target = Target::Ipv6(Ipv6Addr::LOCALHOST, 5353);
        let mut out = Vec::new();
        target.encode(&mut out).unwrap();
        assert_eq!(
            out,
            [
                0x03, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x14, 0xe9,
            ]
        );
    }

    #[test]
    fn roundtrips_ipv6() {
        let target = Target::Ipv6(Ipv6Addr::LOCALHOST, 5353);
        let mut out = Vec::new();
        target.encode(&mut out).unwrap();
        let mut bytes = Bytes::from(out);
        assert_eq!(Target::decode(&mut bytes).unwrap(), target);
    }

    #[test]
    fn log_safe_formats_targets_with_type_prefixes() {
        assert_eq!(
            Target::Domain("api.example.com".to_owned(), 443).log_safe(),
            "domain:api.example.com:443"
        );
        assert_eq!(
            Target::Ipv4(Ipv4Addr::LOCALHOST, 8080).log_safe(),
            "ipv4:127.0.0.1:8080"
        );
        assert_eq!(
            Target::Ipv6(Ipv6Addr::LOCALHOST, 5353).log_safe(),
            "ipv6:[::1]:5353"
        );
    }

    #[test]
    fn log_safe_escapes_domain_text() {
        let target = Target::Domain("quote\"slash\\".to_owned(), 443);

        assert_eq!(target.log_safe(), "domain:quote\\\"slash\\\\:443");
    }

    #[test]
    fn rejects_zero_port() {
        let mut bytes = Bytes::from_static(&[0x02, 0x04, 127, 0, 0, 1, 0, 0]);
        assert_eq!(
            Target::decode(&mut bytes),
            Err(ProtocolError::InvalidTarget("port must be 1..=65535"))
        );
    }

    #[test]
    fn rejects_domain_control_character() {
        let target = Target::Domain("bad\nname".to_owned(), 443);
        let mut out = Vec::new();
        assert_eq!(
            target.encode(&mut out),
            Err(ProtocolError::InvalidTarget(
                "domain contains ascii control character"
            ))
        );
    }

    #[test]
    fn rejects_bad_ipv4_length() {
        let mut bytes = Bytes::from_static(&[0x02, 0x03, 127, 0, 1, 0x00, 0x50]);
        assert_eq!(
            Target::decode(&mut bytes),
            Err(ProtocolError::InvalidTarget("invalid ipv4 length"))
        );
    }

    #[test]
    fn rejects_truncated_target() {
        let mut bytes = Bytes::from_static(&[0x01, 0x0b, b'e']);
        assert_eq!(Target::decode(&mut bytes), Err(ProtocolError::Truncated));
    }
}
