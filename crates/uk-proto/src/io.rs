//! Async frame IO helpers.

use std::io::ErrorKind;

use bytes::{BufMut, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Frame, FrameHeader, FrameLimits, ProtocolError, varint};

/// Result alias for async frame IO.
pub type FrameIoResult<T> = Result<T, FrameIoError>;

/// Errors returned while reading or writing frames.
#[derive(Debug, Error)]
pub enum FrameIoError {
    /// Transport IO error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Protocol decoding or encoding error.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Reads one complete frame from an async stream.
pub async fn read_frame<R>(reader: &mut R, limits: FrameLimits) -> FrameIoResult<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut fixed = [0_u8; 4];
    read_exact_or_truncated(reader, &mut fixed).await?;

    let mut header_bytes = BytesMut::from(&fixed[..]);
    let id = read_varint_async(reader, &mut header_bytes).await?;
    let length = read_varint_async(reader, &mut header_bytes).await?;

    let mut header_src = header_bytes.freeze();
    let header = FrameHeader::decode(&mut header_src, limits)?;
    debug_assert_eq!(header.id, id);
    debug_assert_eq!(header.length, length);

    let payload_len = usize::try_from(header.length).map_err(|_| ProtocolError::InvalidVarint)?;
    let mut payload = BytesMut::zeroed(payload_len);
    read_exact_or_truncated(reader, &mut payload).await?;

    Ok(Frame {
        header,
        payload: payload.freeze(),
    })
}

/// Writes one complete frame to an async stream.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> FrameIoResult<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = frame.encode()?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_varint_async<R>(reader: &mut R, header_bytes: &mut BytesMut) -> FrameIoResult<u64>
where
    R: AsyncRead + Unpin,
{
    let first = read_one(reader).await?;
    header_bytes.put_u8(first);
    let len = 1_usize << (first >> 6);
    if len > 1 {
        let remaining = len - 1;
        let mut rest = vec![0_u8; remaining];
        read_exact_or_truncated(reader, &mut rest).await?;
        header_bytes.extend_from_slice(&rest);
    }

    let start = header_bytes.len() - len;
    let mut varint_bytes = &header_bytes[start..];
    Ok(varint::decode(&mut varint_bytes)?)
}

async fn read_one<R>(reader: &mut R) -> FrameIoResult<u8>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    read_exact_or_truncated(reader, &mut byte).await?;
    Ok(byte[0])
}

async fn read_exact_or_truncated<R>(reader: &mut R, buf: &mut [u8]) -> FrameIoResult<()>
where
    R: AsyncRead + Unpin,
{
    reader.read_exact(buf).await.map_or_else(
        |err| {
            if err.kind() == ErrorKind::UnexpectedEof {
                Err(ProtocolError::Truncated.into())
            } else {
                Err(err.into())
            }
        },
        |_| Ok(()),
    )
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::FrameType;

    #[tokio::test]
    async fn roundtrips_frame_over_duplex() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"abc")).unwrap();
        let outbound = frame.clone();

        let writer = tokio::spawn(async move { write_frame(&mut client, &outbound).await });
        let read = read_frame(&mut server, FrameLimits::default())
            .await
            .unwrap();
        writer.await.unwrap().unwrap();

        assert_eq!(read, frame);
    }

    #[tokio::test]
    async fn rejects_truncated_fixed_header_as_protocol_error() {
        let mut input = &b"\x01\x11"[..];

        let err = read_frame(&mut input, FrameLimits::default())
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            FrameIoError::Protocol(ProtocolError::Truncated)
        ));
    }

    #[tokio::test]
    async fn rejects_truncated_payload_as_protocol_error() {
        let mut input = &b"\x01\x11\x00\x00\x01\x03a"[..];

        let err = read_frame(&mut input, FrameLimits::default())
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            FrameIoError::Protocol(ProtocolError::Truncated)
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_header_without_consuming_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&[0x01, 0x11, 0x00, 0x00, 0x01, 0x03, b'a', b'b', b'c'])
            .await
            .unwrap();

        let err = read_frame(&mut reader, FrameLimits { max_frame_size: 2 })
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            FrameIoError::Protocol(ProtocolError::OversizedFrame {
                length: 3,
                limit: 2
            })
        ));

        let mut remaining = [0_u8; 3];
        reader.read_exact(&mut remaining).await.unwrap();
        assert_eq!(&remaining, b"abc");
    }

    #[tokio::test]
    async fn write_frame_rejects_mismatched_length_before_writing() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let mut frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"abc")).unwrap();
        frame.header.length = 4;

        let err = write_frame(&mut writer, &frame).await.unwrap_err();

        assert!(matches!(
            err,
            FrameIoError::Protocol(ProtocolError::InvalidFrame(
                "frame header length does not match payload length"
            ))
        ));

        drop(writer);

        let mut written = Vec::new();
        reader.read_to_end(&mut written).await.unwrap();
        assert!(written.is_empty());
    }
}
