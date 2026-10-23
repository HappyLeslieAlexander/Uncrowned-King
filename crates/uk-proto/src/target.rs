//! Strict target address encoding.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
            Self::Domain(domain, port) => format!("domain:{}:{port}", escape_log_domain(domain)),
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
        // Early header bounds validation: validate fixed field `addr_type`
        // before decoding variable-length integers or checking buffer sizes.
        if !matches!(addr_type, ADDR_DOMAIN | ADDR_IPV4 | ADDR_IPV6) {
            return Err(ProtocolError::InvalidTarget("unknown address type"));
        }

        let host_len =
            usize::try_from(varint::decode(src)?).map_err(|_| ProtocolError::InvalidVarint)?;

        // Validate `host_len` against `addr_type` BEFORE checking buffer remaining length
        // or allocating memory. This prevents invalid lengths on unknown or mismatched types
        // from returning `Truncated` and causing stream readers to hang waiting for more bytes.
        match addr_type {
            ADDR_DOMAIN if host_len == 0 || host_len > 255 => {
                return Err(ProtocolError::InvalidTarget("invalid domain length"));
            }
            ADDR_IPV4 if host_len != 4 => {
                return Err(ProtocolError::InvalidTarget("invalid ipv4 length"));
            }
            ADDR_IPV6 if host_len != 16 => {
                return Err(ProtocolError::InvalidTarget("invalid ipv6 length"));
            }
            ADDR_DOMAIN | ADDR_IPV4 | ADDR_IPV6 => {}
            _ => unreachable!("addr_type validated above"),
        }

        // `host_len` is attacker-controlled and only bounded by `usize`: on a
        // 32-bit target `usize::try_from` accepts values up to `u32::MAX`, where
        // a plain `+ 2` would wrap to a tiny number, pass this check and panic
        // in `copy_to_bytes` below.
        if src.remaining() < host_len.saturating_add(2) {
            return Err(ProtocolError::Truncated);
        }

        let host = src.copy_to_bytes(host_len);
        let port = src.get_u16();
        validate_port(port)?;

        match addr_type {
            ADDR_DOMAIN => {
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
            // SAFETY: unreachable — the match above rejects unknown types.
            _ => Err(ProtocolError::InvalidTarget("unknown address type")),
        }
    }
}

// Renders a domain so it can never introduce a field boundary in a logfmt-style
// line. `escape_debug` covers quotes, backslashes and control characters, but
// leaves the space and `=` that `validate_domain` also permits, so a requested
// domain such as `a event=auth.bypass x` would otherwise forge an `event` field
// in `target=domain:...`. Space and `=` are the only unescaped ASCII characters
// with that power: every other logfmt separator is a control character already.
fn escape_log_domain(domain: &str) -> String {
    let mut out = String::with_capacity(domain.len());
    for ch in domain.chars() {
        match ch {
            ' ' => out.push_str("\\x20"),
            '=' => out.push_str("\\x3d"),
            _ => out.extend(ch.escape_debug()),
        }
    }
    out
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
    if domain.parse::<IpAddr>().is_ok() {
        return Err(ProtocolError::InvalidTarget(
            "domain must not be an IP literal",
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(ProtocolError::InvalidTarget(
            "malformed domain dot structure",
        ));
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(ProtocolError::InvalidTarget(
            "domain contains invalid characters",
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ProtocolError::InvalidTarget("invalid domain label length"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ProtocolError::InvalidTarget(
                "domain label cannot start or end with hyphen",
            ));
        }
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
    fn log_safe_escapes_logfmt_field_separators() {
        let target = Target::Domain("a event=auth.bypass x".to_owned(), 443);

        assert_eq!(
            target.log_safe(),
            "domain:a\\x20event\\x3dauth.bypass\\x20x:443"
        );
    }

    #[test]
    fn rejects_truncated_target() {
        let mut bytes = Bytes::from_static(&[0x01, 0x0b, b'e']);
        assert_eq!(Target::decode(&mut bytes), Err(ProtocolError::Truncated));
    }

    #[test]
    fn rejects_unknown_address_type_early() {
        // Even with truncated buffer or huge varint, unknown addr_type must fail immediately
        let mut bytes = Bytes::from_static(&[0xff, 0xc0, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            Target::decode(&mut bytes),
            Err(ProtocolError::InvalidTarget("unknown address type"))
        );
    }

    #[test]
    fn rejects_huge_declared_host_length() {
        // `0xffff_ffff` as a minimal varint: large enough to wrap `host_len + 2`
        // on a 32-bit target, where `usize::try_from` still succeeds.
        // Validating `host_len` against `addr_type` before buffer length checks
        // rejects this as invalid domain length immediately rather than Truncated.
        let mut bytes = Bytes::from_static(&[
            0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, b'a', 0x01, 0xbb,
        ]);
        assert_eq!(
            Target::decode(&mut bytes),
            Err(ProtocolError::InvalidTarget("invalid domain length"))
        );
    }

    #[test]
    fn rejects_invalid_address_type_with_large_declared_length_immediately() {
        // Unknown address type 0x7f with large declared length varint (e.g. 1000)
        // must fail immediately with InvalidTarget("unknown address type")
        // without waiting or returning Truncated.
        let mut bytes = Bytes::from_static(&[0x7f, 0x80, 0x00, 0x03, 0xe8]);
        assert_eq!(
            Target::decode(&mut bytes),
            Err(ProtocolError::InvalidTarget("unknown address type"))
        );
    }

    #[test]
    fn rejects_non_minimal_host_length_varint() {
        // `0x40, 0x04` is a legal QUIC spelling of 4, but not a legal UK one.
        let mut bytes = Bytes::from_static(&[0x02, 0x40, 0x04, 127, 0, 0, 1, 0x1f, 0x90]);
        assert_eq!(
            Target::decode(&mut bytes),
            Err(ProtocolError::InvalidVarint)
        );
    }

    #[test]
    fn rejects_ip_literals_as_domain() {
        let ipv4 = Target::Domain("127.0.0.1".to_owned(), 80);
        let mut out = Vec::new();
        assert_eq!(
            ipv4.encode(&mut out),
            Err(ProtocolError::InvalidTarget(
                "domain must not be an IP literal"
            ))
        );

        let ipv6 = Target::Domain("::1".to_owned(), 80);
        assert_eq!(
            ipv6.encode(&mut out),
            Err(ProtocolError::InvalidTarget(
                "domain must not be an IP literal"
            ))
        );

        let mut bytes = Bytes::from_static(&[
            0x01, 0x09, b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1', 0x00, 0x50,
        ]);
        assert_eq!(
            Target::decode(&mut bytes),
            Err(ProtocolError::InvalidTarget(
                "domain must not be an IP literal"
            ))
        );
    }

    #[test]
    fn rejects_malformed_domain_dot_structures() {
        let mut out = Vec::new();
        let bad_dots = [".example.com", "example.com.", "example..com"];
        for domain in bad_dots {
            let target = Target::Domain(domain.to_owned(), 80);
            assert_eq!(
                target.encode(&mut out),
                Err(ProtocolError::InvalidTarget(
                    "malformed domain dot structure"
                )),
                "failed on {domain}"
            );
        }
    }

    #[test]
    fn rejects_invalid_domain_characters() {
        let mut out = Vec::new();
        let bad_chars = [
            "example.com/admin",
            "example.com:80",
            "example.com@bad",
            "foo_bar.com",
            "a b.com",
        ];
        for domain in bad_chars {
            let target = Target::Domain(domain.to_owned(), 80);
            assert_eq!(
                target.encode(&mut out),
                Err(ProtocolError::InvalidTarget(
                    "domain contains invalid characters"
                )),
                "failed on {domain}"
            );
        }
    }

    #[test]
    fn rejects_invalid_domain_label_boundaries() {
        let mut out = Vec::new();
        let bad_labels = ["-example.com", "example-.com", "sub.-bad.org"];
        for domain in bad_labels {
            let target = Target::Domain(domain.to_owned(), 80);
            assert_eq!(
                target.encode(&mut out),
                Err(ProtocolError::InvalidTarget(
                    "domain label cannot start or end with hyphen"
                )),
                "failed on {domain}"
            );
        }
    }

    #[test]
    fn accepts_valid_rfc1123_domains() {
        let mut out = Vec::new();
        let valid_domains = [
            "example.com",
            "api.v2.service.corp",
            "host-1.example.org",
            "com",
        ];
        for domain in valid_domains {
            out.clear();
            let target = Target::Domain(domain.to_owned(), 443);
            assert!(target.encode(&mut out).is_ok());
        }
    }
}
