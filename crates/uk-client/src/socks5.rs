//! Minimal SOCKS5 CONNECT parser.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uk_proto::Target;

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequestHead {
    command: u8,
    addr_type: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NotAllowed = 0x02,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    Connect(Target),
    UdpAssociate(SocksEndpoint),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SocksEndpoint {
    Ipv4(Ipv4Addr, u16),
    Domain(String, u16),
    Ipv6(Ipv6Addr, u16),
}

impl Reply {
    const fn code(self) -> u8 {
        self as u8
    }
}

impl From<SocketAddr> for SocksEndpoint {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => Self::Ipv4(*addr.ip(), addr.port()),
            SocketAddr::V6(addr) => Self::Ipv6(*addr.ip(), addr.port()),
        }
    }
}

#[cfg(test)]
async fn negotiate_connect<S>(stream: &mut S) -> io::Result<Target>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match negotiate_request(stream).await? {
        Request::Connect(target) => Ok(target),
        Request::UdpAssociate(_) => {
            send_reply(stream, Reply::CommandNotSupported).await?;
            Err(protocol_error("socks UDP ASSOCIATE is not enabled"))
        }
    }
}

pub(crate) async fn negotiate_request<S>(stream: &mut S) -> io::Result<Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_greeting(stream).await?;
    send_method_selection(stream, METHOD_NO_AUTH).await?;
    read_request(stream).await
}

pub(crate) async fn send_reply<S>(stream: &mut S, reply: Reply) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    send_reply_with_endpoint(
        stream,
        reply,
        &SocksEndpoint::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
    )
    .await
}

pub(crate) async fn send_reply_with_endpoint<S>(
    stream: &mut S,
    reply: Reply,
    endpoint: &SocksEndpoint,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut payload = Vec::with_capacity(22);
    payload.extend_from_slice(&[VERSION, reply.code(), 0x00]);
    encode_endpoint(endpoint, &mut payload)?;
    stream.write_all(&payload).await?;
    stream.flush().await
}

async fn read_greeting<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(protocol_error("unsupported socks version"));
    }
    let method_count = match stream.read_u8().await {
        Ok(method_count) => method_count,
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            let _ = send_method_selection(stream, METHOD_NO_ACCEPTABLE).await;
            return Err(protocol_error("truncated socks greeting"));
        }
        Err(err) => return Err(err),
    };
    if method_count == 0 {
        send_method_selection(stream, METHOD_NO_ACCEPTABLE).await?;
        return Err(protocol_error("socks greeting has no methods"));
    }

    let mut methods = vec![0_u8; usize::from(method_count)];
    read_greeting_exact(stream, &mut methods).await?;
    if methods.contains(&METHOD_NO_AUTH) {
        Ok(())
    } else {
        send_method_selection(stream, METHOD_NO_ACCEPTABLE).await?;
        Err(protocol_error("socks client offered no supported method"))
    }
}

async fn send_method_selection<S>(stream: &mut S, method: u8) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[VERSION, method]).await?;
    stream.flush().await
}

async fn read_greeting_exact<S>(stream: &mut S, buf: &mut [u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            let _ = send_method_selection(stream, METHOD_NO_ACCEPTABLE).await;
            Err(protocol_error("truncated socks greeting"))
        }
        Err(err) => Err(err),
    }
}

async fn read_request<S>(stream: &mut S) -> io::Result<Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_request_head(stream).await?;

    match head.command {
        CMD_CONNECT => {
            let endpoint = read_endpoint(stream, head.addr_type).await?;
            let target = match target_from_endpoint(endpoint) {
                Ok(target) => target,
                Err(err) => {
                    send_reply(stream, Reply::HostUnreachable).await?;
                    return Err(err);
                }
            };
            Ok(Request::Connect(target))
        }
        CMD_UDP_ASSOCIATE => {
            let endpoint = read_endpoint(stream, head.addr_type).await?;
            if let Err(err) = validate_udp_associate_endpoint(&endpoint) {
                send_reply(stream, Reply::HostUnreachable).await?;
                return Err(err);
            }
            Ok(Request::UdpAssociate(endpoint))
        }
        _ => {
            send_reply(stream, Reply::CommandNotSupported).await?;
            Err(protocol_error("unsupported socks command"))
        }
    }
}

async fn read_request_head<S>(stream: &mut S) -> io::Result<RequestHead>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0_u8; 4];
    read_request_exact(stream, &mut head).await?;

    let [version, command, reserved, addr_type] = head;
    if version != VERSION {
        send_reply(stream, Reply::GeneralFailure).await?;
        return Err(protocol_error("unsupported socks request version"));
    }
    if reserved != 0 {
        send_reply(stream, Reply::GeneralFailure).await?;
        return Err(protocol_error("invalid socks reserved byte"));
    }
    Ok(RequestHead { command, addr_type })
}

async fn read_port<S>(stream: &mut S) -> io::Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut port = [0_u8; 2];
    read_request_exact(stream, &mut port).await?;
    Ok(u16::from_be_bytes(port))
}

async fn read_endpoint<S>(stream: &mut S, addr_type: u8) -> io::Result<SocksEndpoint>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match addr_type {
        ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            read_request_exact(stream, &mut octets).await?;
            let port = read_port(stream).await?;
            Ok(SocksEndpoint::Ipv4(Ipv4Addr::from(octets), port))
        }
        ATYP_DOMAIN => {
            let mut len = [0_u8; 1];
            read_request_exact(stream, &mut len).await?;
            let mut domain = vec![0_u8; usize::from(len[0])];
            read_request_exact(stream, &mut domain).await?;
            let port = read_port(stream).await?;
            let Ok(domain) = String::from_utf8(domain) else {
                send_reply(stream, Reply::HostUnreachable).await?;
                return Err(protocol_error("socks domain is not utf-8"));
            };
            Ok(SocksEndpoint::Domain(domain, port))
        }
        ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            read_request_exact(stream, &mut octets).await?;
            let port = read_port(stream).await?;
            Ok(SocksEndpoint::Ipv6(Ipv6Addr::from(octets), port))
        }
        _ => {
            send_reply(stream, Reply::AddressTypeNotSupported).await?;
            Err(protocol_error("unsupported socks address type"))
        }
    }
}

async fn read_request_exact<S>(stream: &mut S, buf: &mut [u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            let _ = send_reply(stream, Reply::GeneralFailure).await;
            Err(protocol_error("truncated socks request"))
        }
        Err(err) => Err(err),
    }
}

fn validate_target(target: &Target) -> io::Result<()> {
    let mut discard = Vec::new();
    target
        .encode(&mut discard)
        .map_err(|err| protocol_error(err.to_string()))
}

fn target_from_endpoint(endpoint: SocksEndpoint) -> io::Result<Target> {
    let target = match endpoint {
        SocksEndpoint::Ipv4(addr, port) => Target::Ipv4(addr, port),
        SocksEndpoint::Domain(domain, port) => Target::Domain(domain, port),
        SocksEndpoint::Ipv6(addr, port) => Target::Ipv6(addr, port),
    };
    validate_target(&target)?;
    Ok(target)
}

fn validate_udp_associate_endpoint(endpoint: &SocksEndpoint) -> io::Result<()> {
    if let SocksEndpoint::Domain(domain, _) = endpoint {
        validate_domain(domain)?;
    }
    Ok(())
}

fn validate_domain(domain: &str) -> io::Result<()> {
    if domain.is_empty() || domain.len() > 255 {
        return Err(protocol_error("invalid socks domain length"));
    }
    if domain.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(protocol_error(
            "socks domain contains ascii control character",
        ));
    }
    Ok(())
}

fn encode_endpoint(endpoint: &SocksEndpoint, out: &mut Vec<u8>) -> io::Result<()> {
    match endpoint {
        SocksEndpoint::Ipv4(addr, port) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        SocksEndpoint::Domain(domain, port) => {
            validate_domain(domain)?;
            let len = u8::try_from(domain.len())
                .map_err(|_| protocol_error("invalid socks domain length"))?;
            out.push(ATYP_DOMAIN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        SocksEndpoint::Ipv6(addr, port) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn assert_request_failure_after_shutdown(request: &[u8], expected_reply: Reply) {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], expected_reply.code());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn negotiates_ipv4_connect() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90,
            ])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let target = server_task.await.unwrap().unwrap();
        assert_eq!(target, Target::Ipv4(Ipv4Addr::LOCALHOST, 8080));
    }

    #[tokio::test]
    async fn negotiates_ipv6_connect() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });
        let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04];
        request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        request.extend_from_slice(&443_u16.to_be_bytes());

        client.write_all(&request).await.unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let target = server_task.await.unwrap().unwrap();
        assert_eq!(target, Target::Ipv6(Ipv6Addr::LOCALHOST, 443));
    }

    #[tokio::test]
    async fn negotiates_domain_connect() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });
        let domain = b"example.com";
        let mut request = vec![
            0x05,
            0x01,
            0x00,
            0x05,
            0x01,
            0x00,
            0x03,
            u8::try_from(domain.len()).unwrap(),
        ];
        request.extend_from_slice(domain);
        request.extend_from_slice(&443_u16.to_be_bytes());

        client.write_all(&request).await.unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let target = server_task.await.unwrap().unwrap();
        assert_eq!(target, Target::Domain("example.com".to_owned(), 443));
    }

    #[tokio::test]
    async fn negotiates_udp_associate_unspecified_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_request(&mut server).await });

        client
            .write_all(&[
                0x05,
                0x01,
                0x00,
                0x05,
                CMD_UDP_ASSOCIATE,
                0x00,
                ATYP_IPV4,
                0,
                0,
                0,
                0,
                0x00,
                0x00,
            ])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let request = server_task.await.unwrap().unwrap();
        assert_eq!(
            request,
            Request::UdpAssociate(SocksEndpoint::Ipv4(Ipv4Addr::UNSPECIFIED, 0))
        );
    }

    #[tokio::test]
    async fn negotiates_udp_associate_domain_with_zero_port() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_request(&mut server).await });
        let domain = b"client.local";
        let mut request = vec![
            0x05,
            0x01,
            0x00,
            0x05,
            CMD_UDP_ASSOCIATE,
            0x00,
            ATYP_DOMAIN,
            u8::try_from(domain.len()).unwrap(),
        ];
        request.extend_from_slice(domain);
        request.extend_from_slice(&0_u16.to_be_bytes());

        client.write_all(&request).await.unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let request = server_task.await.unwrap().unwrap();
        assert_eq!(
            request,
            Request::UdpAssociate(SocksEndpoint::Domain("client.local".to_owned(), 0))
        );
    }

    #[tokio::test]
    async fn connect_only_negotiation_rejects_udp_associate() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[
                0x05,
                0x01,
                0x00,
                0x05,
                CMD_UDP_ASSOCIATE,
                0x00,
                ATYP_IPV4,
                0,
                0,
                0,
                0,
                0x00,
                0x00,
            ])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::CommandNotSupported.code());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn encodes_bound_ipv4_reply() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let endpoint = SocksEndpoint::from(SocketAddr::from(([127, 0, 0, 1], 5353)));

        let server_task = tokio::spawn(async move {
            send_reply_with_endpoint(&mut server, Reply::Succeeded, &endpoint).await
        });

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply,
            [0x05, 0x00, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x14, 0xe9]
        );
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_greeting_without_methods() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client.write_all(&[0x05, 0x00]).await.unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0xff]);
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_greeting_without_no_auth_method() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client.write_all(&[0x05, 0x02, 0x01, 0x02]).await.unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0xff]);
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_truncated_greeting_with_no_acceptable_method() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client.write_all(&[0x05, 0x02, 0x00]).await.unwrap();
        client.shutdown().await.unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0xff]);
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_truncated_greeting_head_with_no_acceptable_method() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client.write_all(&[0x05]).await.unwrap();
        client.shutdown().await.unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0xff]);
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_missing_request_head_with_failure_reply() {
        assert_request_failure_after_shutdown(&[0x05, 0x01, 0x00], Reply::GeneralFailure).await;
    }

    #[tokio::test]
    async fn rejects_unsupported_command() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50,
            ])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::CommandNotSupported.code());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_unsupported_address_type() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::AddressTypeNotSupported.code());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_bad_request_version_with_failure_reply() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50,
            ])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::GeneralFailure.code());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_truncated_ipv4_request_with_failure_reply() {
        assert_request_failure_after_shutdown(
            &[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127],
            Reply::GeneralFailure,
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_truncated_domain_request_with_failure_reply() {
        assert_request_failure_after_shutdown(
            &[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x0b, b'e'],
            Reply::GeneralFailure,
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_truncated_domain_port_with_failure_reply() {
        assert_request_failure_after_shutdown(
            &[
                0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x03, b'c', b'o', b'm', 0x01,
            ],
            Reply::GeneralFailure,
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_bad_reserved_byte_with_failure_reply() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x05, 0x01, 0xff, 0x01, 127, 0, 0, 1, 0x00, 0x50,
            ])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::GeneralFailure.code());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_zero_port_with_failure_reply() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00,
            ])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::HostUnreachable.code());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_domain_with_failure_reply() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x01, 0xff, 0x00, 0x50,
            ])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::HostUnreachable.code());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_empty_domain_with_failure_reply() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move { negotiate_connect(&mut server).await });

        client
            .write_all(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50])
            .await
            .unwrap();

        let mut method_response = [0_u8; 2];
        client.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [0x05, 0x00]);

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::HostUnreachable.code());
        assert!(server_task.await.unwrap().is_err());
    }
}
