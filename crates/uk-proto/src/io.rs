//! Async frame IO helpers.

use bytes::{BufMut, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Frame, FrameHeader, FrameLimits, ProtocolError, ProtocolResult, varint};

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
    reader.read_exact(&mut fixed).await?;

    let mut header_bytes = BytesMut::from(&fixed[..]);
    let id = read_varint_async(reader, &mut header_bytes).await?;
    let length = read_varint_async(reader, &mut header_bytes).await?;

    let mut header_src = header_bytes.freeze();
    let header = FrameHeader::decode(&mut header_src, limits)?;
    debug_assert_eq!(header.id, id);
    debug_assert_eq!(header.length, length);

    let payload_len = usize::try_from(header.length).map_err(|_| ProtocolError::InvalidVarint)?;
    let mut payload = BytesMut::zeroed(payload_len);
    reader.read_exact(&mut payload).await?;

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

async fn read_varint_async<R>(reader: &mut R, header_bytes: &mut BytesMut) -> ProtocolResult<u64>
where
    R: AsyncRead + Unpin,
{
    let first = read_one(reader).await?;
    header_bytes.put_u8(first);
    let len = 1_usize << (first >> 6);
    if len > 1 {
        let remaining = len - 1;
        let mut rest = vec![0_u8; remaining];
        reader
            .read_exact(&mut rest)
            .await
            .map_err(|_| ProtocolError::Truncated)?;
        header_bytes.extend_from_slice(&rest);
    }

    let start = header_bytes.len() - len;
    let mut varint_bytes = &header_bytes[start..];
    varint::decode(&mut varint_bytes)
}

async fn read_one<R>(reader: &mut R) -> ProtocolResult<u8>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    reader
        .read_exact(&mut byte)
        .await
        .map_err(|_| ProtocolError::Truncated)?;
    Ok(byte[0])
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

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
}
