//! Minimal SOCKS5 CONNECT parser.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uk_proto::Target;

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

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

impl Reply {
    const fn code(self) -> u8 {
        self as u8
    }
}

pub(crate) async fn negotiate_connect<S>(stream: &mut S) -> io::Result<Target>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_greeting(stream).await?;
    stream.write_all(&[VERSION, METHOD_NO_AUTH]).await?;
    stream.flush().await?;
    read_connect_request(stream).await
}

pub(crate) async fn send_reply<S>(stream: &mut S, reply: Reply) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, reply.code(), 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
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
    let method_count = stream.read_u8().await?;
    if method_count == 0 {
        stream.write_all(&[VERSION, METHOD_NO_ACCEPTABLE]).await?;
        stream.flush().await?;
        return Err(protocol_error("socks greeting has no methods"));
    }

    let mut methods = vec![0_u8; usize::from(method_count)];
    stream.read_exact(&mut methods).await?;
    if methods.contains(&METHOD_NO_AUTH) {
        Ok(())
    } else {
        stream.write_all(&[VERSION, METHOD_NO_ACCEPTABLE]).await?;
        stream.flush().await?;
        Err(protocol_error("socks client offered no supported method"))
    }
}

async fn read_connect_request<S>(stream: &mut S) -> io::Result<Target>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        send_reply(stream, Reply::GeneralFailure).await?;
        return Err(protocol_error("unsupported socks request version"));
    }
    let command = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    if reserved != 0 {
        send_reply(stream, Reply::GeneralFailure).await?;
        return Err(protocol_error("invalid socks reserved byte"));
    }
    let addr_type = stream.read_u8().await?;
    if command != CMD_CONNECT {
        send_reply(stream, Reply::CommandNotSupported).await?;
        return Err(protocol_error("only socks CONNECT is supported"));
    }

    let target = match addr_type {
        ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            let port = read_port(stream).await?;
            Target::Ipv4(Ipv4Addr::from(octets), port)
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await?;
            let mut domain = vec![0_u8; usize::from(len)];
            stream.read_exact(&mut domain).await?;
            let port = read_port(stream).await?;
            let Ok(domain) = String::from_utf8(domain) else {
                send_reply(stream, Reply::HostUnreachable).await?;
                return Err(protocol_error("socks domain is not utf-8"));
            };
            Target::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            let port = read_port(stream).await?;
            Target::Ipv6(Ipv6Addr::from(octets), port)
        }
        _ => {
            send_reply(stream, Reply::AddressTypeNotSupported).await?;
            return Err(protocol_error("unsupported socks address type"));
        }
    };

    if let Err(err) = validate_target(&target) {
        send_reply(stream, Reply::HostUnreachable).await?;
        return Err(err);
    }
    Ok(target)
}

async fn read_port<S>(stream: &mut S) -> io::Result<u16>
where
    S: AsyncRead + Unpin,
{
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

fn validate_target(target: &Target) -> io::Result<()> {
    let mut discard = Vec::new();
    target
        .encode(&mut discard)
        .map_err(|err| protocol_error(err.to_string()))
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

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
