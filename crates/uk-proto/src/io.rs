//! Async frame IO helpers.

use std::io::ErrorKind;

use bytes::{BufMut, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    Frame, FrameHeader, FrameLimits, FrameType, ProtocolError, VERSION, frame::validate_flags,
    varint,
};

/// Result alias for async frame IO.
pub type FrameIoResult<T> = Result<T, FrameIoError>;

/// Errors returned while reading or writing frames.
#[derive(Debug, Error)]
pub enum FrameIoError {
    /// The peer closed the stream before starting another frame.
    #[error("stream closed")]
    Closed,
    /// Transport IO error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Protocol decoding or encoding error.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Largest amount of buffer capacity reserved ahead of the bytes actually read.
///
/// A frame header is as small as six bytes but may declare a payload up to
/// `max_frame_size`. Reserving the whole declared payload up front would let a
/// peer commit that much memory per session without sending any of it, so
/// capacity grows in bounded steps as the payload actually arrives.
const READ_RESERVE_CHUNK: usize = 256 * 1024;

/// Smallest amount of spare capacity offered to a single read.
const MIN_READ_RESERVE: usize = 64;

/// Reads one complete frame from an async stream.
///
/// # Cancellation safety
///
/// This function is **not** cancellation safe. Partially decoded state lives in
/// the returned future, so dropping it — which `tokio::select!` does to every
/// branch that loses the race — discards any bytes it had already taken from
/// `reader` and desynchronises the frame stream. Use it only where the future
/// is awaited to completion, or where the carrier is discarded on cancellation.
/// Use [`FrameReader`] inside `select!`.
pub async fn read_frame<R>(reader: &mut R, limits: FrameLimits) -> FrameIoResult<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut fixed = [0_u8; 4];
    let Some(first) = read_optional_one(reader).await? else {
        return Err(FrameIoError::Closed);
    };
    fixed[0] = first;
    read_exact_or_truncated(reader, &mut fixed[1..]).await?;

    let version = fixed[0];
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion(version).into());
    }
    let _frame_type = FrameType::try_from(fixed[1])?;
    let flags = u16::from_be_bytes([fixed[2], fixed[3]]);
    validate_flags(flags)?;

    let mut header_bytes = BytesMut::from(&fixed[..]);
    let id = read_varint_async(reader, &mut header_bytes).await?;
    let length = read_varint_async(reader, &mut header_bytes).await?;

    let mut header_src = header_bytes.freeze();
    let header = FrameHeader::decode(&mut header_src, limits)?;
    debug_assert_eq!(header.id, id);
    debug_assert_eq!(header.length, length);

    let payload_len = usize::try_from(header.length).map_err(|_| ProtocolError::InvalidVarint)?;
    let mut payload = BytesMut::new();
    let mut remaining = payload_len;
    let mut buf = [0_u8; 8192];
    while remaining > 0 {
        let chunk_size = remaining.min(READ_RESERVE_CHUNK);
        payload.reserve(chunk_size);
        let to_read = remaining.min(buf.len());
        read_exact_or_truncated(reader, &mut buf[..to_read]).await?;
        payload.extend_from_slice(&buf[..to_read]);
        remaining -= to_read;
    }

    Ok(Frame {
        header,
        payload: payload.freeze(),
    })
}

/// A buffered frame reader whose decode state survives cancellation.
///
/// [`read_frame`] keeps the bytes it has consumed so far inside the future, so
/// dropping that future mid-frame destroys them and the next read resynchronises
/// part-way through a frame. `FrameReader` keeps those bytes in the struct
/// instead, so a cancelled read loses nothing and the next call resumes exactly
/// where the previous one stopped.
#[derive(Debug)]
pub struct FrameReader<R> {
    reader: R,
    buffer: BytesMut,
    limits: FrameLimits,
}

impl<R> FrameReader<R> {
    /// Wraps `reader`, decoding frames under `limits`.
    pub fn new(reader: R, limits: FrameLimits) -> Self {
        Self {
            reader,
            buffer: BytesMut::new(),
            limits,
        }
    }
}

impl<R> FrameReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Reads one complete frame, buffering across calls.
    ///
    /// # Cancellation safety
    ///
    /// This method is cancellation safe. Bytes read from the underlying stream
    /// are appended to an internal buffer before any of them are decoded, so
    /// dropping the returned future — for example when another `tokio::select!`
    /// branch completes first — never discards data. The next call resumes from
    /// the buffered prefix.
    pub async fn read_frame(&mut self) -> FrameIoResult<Frame> {
        loop {
            if let Some(frame) = self.take_buffered_frame()? {
                return Ok(frame);
            }
            self.reserve_for_pending_frame();

            // `read_buf` is itself cancellation safe: if it is dropped before
            // completing, nothing has been read and nothing is lost.
            let read = match self.reader.read_buf(&mut self.buffer).await {
                Ok(read) => read,
                // rustls reports a missing close_notify this way; treat it as a
                // plain end of stream, matching `read_optional_one`.
                Err(err) if err.kind() == ErrorKind::UnexpectedEof => 0,
                Err(err) => return Err(err.into()),
            };
            if read == 0 {
                return if self.buffer.is_empty() {
                    Err(FrameIoError::Closed)
                } else {
                    Err(ProtocolError::Truncated.into())
                };
            }
        }
    }

    /// Decodes one frame from the buffer, or returns `None` if more bytes are
    /// needed. The buffer is left untouched unless a whole frame is removed.
    fn take_buffered_frame(&mut self) -> FrameIoResult<Option<Frame>> {
        let mut cursor = &self.buffer[..];
        let header = match FrameHeader::decode(&mut cursor, self.limits) {
            Ok(header) => header,
            Err(ProtocolError::Truncated) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let header_len = self.buffer.len() - cursor.len();
        let payload_len =
            usize::try_from(header.length).map_err(|_| ProtocolError::InvalidVarint)?;
        let total = header_len
            .checked_add(payload_len)
            .ok_or(ProtocolError::InvalidVarint)?;
        if self.buffer.len() < total {
            return Ok(None);
        }

        let mut frame = self.buffer.split_to(total);
        let payload = frame.split_off(header_len).freeze();
        Ok(Some(Frame { header, payload }))
    }

    /// Grows the buffer towards the pending frame in bounded steps.
    fn reserve_for_pending_frame(&mut self) {
        let mut cursor = &self.buffer[..];
        let wanted = match FrameHeader::decode(&mut cursor, self.limits) {
            Ok(header) => {
                let header_len = self.buffer.len() - cursor.len();
                usize::try_from(header.length)
                    .ok()
                    .and_then(|payload_len| header_len.checked_add(payload_len))
                    .and_then(|total| total.checked_sub(self.buffer.len()))
                    .unwrap_or(READ_RESERVE_CHUNK)
            }
            // The header itself is still incomplete, so only a few bytes are
            // outstanding; any error here resurfaces from `take_buffered_frame`.
            Err(_) => 1,
        };
        // Floor the request so an incomplete header does not degenerate into
        // single-byte reads; `reserve` is a no-op when the spare capacity is
        // already large enough.
        self.buffer
            .reserve(wanted.clamp(MIN_READ_RESERVE, READ_RESERVE_CHUNK));
    }
}

/// Maximum wire size of a [`FrameHeader`]; see [`FrameHeader::MAX_ENCODED_LEN`].
const MAX_FRAME_HEADER_LEN: usize = FrameHeader::MAX_ENCODED_LEN;

/// Writes one complete frame to an async stream.
///
/// The header is encoded into a small stack buffer and written together with
/// the payload via a vectored write, so no intermediate allocation is needed
/// (unlike [`Frame::encode`], which concatenates header and payload into a
/// fresh buffer). The bytes on the wire are identical.
///
/// # Cancellation safety
///
/// This function is **not** cancellation safe: dropping the returned future can
/// leave a partially written frame on the wire. Callers that race it against a
/// shutdown signal must discard the carrier rather than write to it again.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> FrameIoResult<()>
where
    W: AsyncWrite + Unpin,
{
    // Preserve the header/payload consistency check that `Frame::encode_into`
    // performs, so malformed frames are rejected before any bytes go out.
    let payload_len =
        u64::try_from(frame.payload.len()).map_err(|_| ProtocolError::InvalidVarint)?;
    if frame.header.length != payload_len {
        return Err(ProtocolError::InvalidFrame(
            "frame header length does not match payload length",
        )
        .into());
    }
    let mut header_buf = [0u8; MAX_FRAME_HEADER_LEN];
    let header_len = {
        let mut dst: &mut [u8] = &mut header_buf;
        let before = dst.len();
        frame.header.encode(&mut dst)?;
        before - dst.len()
    };
    write_all_vectored(writer, &header_buf[..header_len], &frame.payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Writes two byte slices fully via vectored writes.
async fn write_all_vectored<W>(
    writer: &mut W,
    mut first: &[u8],
    mut second: &[u8],
) -> FrameIoResult<()>
where
    W: AsyncWrite + Unpin,
{
    use std::io::IoSlice;
    while !first.is_empty() || !second.is_empty() {
        let slices = [IoSlice::new(first), IoSlice::new(second)];
        // Skip a leading empty slice so writers never see a zero-length head.
        let active = if first.is_empty() {
            &slices[1..]
        } else {
            &slices[..]
        };
        let written = std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut *writer).poll_write_vectored(cx, active)
        })
        .await?;
        if written == 0 {
            return Err(std::io::Error::new(ErrorKind::WriteZero, "failed to write frame").into());
        }
        let mut remaining = written;
        let first_take = first.len().min(remaining);
        first = &first[first_take..];
        remaining -= first_take;
        let second_take = second.len().min(remaining);
        second = &second[second_take..];
    }
    Ok(())
}

/// Writes multiple frames coalesced into a single contiguous buffer to an async stream.
///
/// This reduces write system calls and minimizes packet fragmentation when sending
/// batches of frames.
///
/// This is part of the stable 1.0 public API: the signature is frozen and the
/// relay hot path depends on it.
///
/// # Cancellation safety
///
/// This function is **not** cancellation safe: dropping the returned future can
/// leave a partially written frame on the wire. Callers that race it against a
/// shutdown signal must discard the carrier rather than write to it again.
pub async fn write_frames<'a, W, I>(writer: &mut W, frames: I) -> FrameIoResult<()>
where
    W: AsyncWrite + Unpin,
    I: IntoIterator<Item = &'a Frame>,
{
    let mut buffer = BytesMut::new();
    for frame in frames {
        frame.encode_into(&mut buffer)?;
    }
    if !buffer.is_empty() {
        writer.write_all(&buffer).await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn read_optional_one<R>(reader: &mut R) -> FrameIoResult<Option<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    match reader.read(&mut byte).await {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(byte[0])),
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(None),
        Err(err) => Err(err.into()),
    }
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
        let mut rest = [0_u8; 7];
        read_exact_or_truncated(reader, &mut rest[..remaining]).await?;
        header_bytes.extend_from_slice(&rest[..remaining]);
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
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    use super::*;
    use crate::FrameType;

    struct UnexpectedEofReader;

    impl AsyncRead for UnexpectedEofReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(ErrorKind::UnexpectedEof, "tls eof")))
        }
    }

    #[tokio::test]
    async fn returns_closed_before_next_frame_starts() {
        let mut input = &b""[..];

        let err = read_frame(&mut input, FrameLimits::default())
            .await
            .unwrap_err();

        assert!(matches!(err, FrameIoError::Closed));
    }

    #[tokio::test]
    async fn returns_closed_for_unexpected_eof_before_next_frame_starts() {
        let mut input = UnexpectedEofReader;

        let err = read_frame(&mut input, FrameLimits::default())
            .await
            .unwrap_err();

        assert!(matches!(err, FrameIoError::Closed));
    }

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
    async fn frame_reader_roundtrips_frames_split_across_reads() {
        let (mut peer, carrier) = tokio::io::duplex(128);
        let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"abcdef")).unwrap();
        let wire = frame.encode().unwrap();
        let mut reader = FrameReader::new(carrier, FrameLimits::default());

        peer.write_all(&wire[..3]).await.unwrap();
        peer.write_all(&wire[3..]).await.unwrap();

        assert_eq!(reader.read_frame().await.unwrap(), frame);
    }

    #[tokio::test]
    async fn frame_reader_reads_two_frames_from_one_segment() {
        let (mut peer, carrier) = tokio::io::duplex(128);
        let first = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"aa")).unwrap();
        let second = Frame::new(FrameType::TcpData, 0, 3, Bytes::from_static(b"bb")).unwrap();
        let mut wire = first.encode().unwrap().to_vec();
        wire.extend_from_slice(&second.encode().unwrap());
        let mut reader = FrameReader::new(carrier, FrameLimits::default());

        peer.write_all(&wire).await.unwrap();

        assert_eq!(reader.read_frame().await.unwrap(), first);
        assert_eq!(reader.read_frame().await.unwrap(), second);
    }

    /// The regression this type exists for: a read cancelled part-way through a
    /// frame must not consume the bytes it had already taken from the stream.
    #[tokio::test]
    async fn frame_reader_read_is_cancel_safe_mid_frame() {
        let (mut peer, carrier) = tokio::io::duplex(128);
        let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"abcdef")).unwrap();
        let wire = frame.encode().unwrap();
        let mut reader = FrameReader::new(carrier, FrameLimits::default());

        peer.write_all(&wire[..4]).await.unwrap();
        peer.flush().await.unwrap();

        // Cancel repeatedly while the frame is incomplete using deterministic polling.
        for _ in 0..8 {
            let mut read_fut = std::pin::pin!(reader.read_frame());
            let completed = std::future::poll_fn(|cx| match read_fut.as_mut().poll(cx) {
                std::task::Poll::Ready(res) => std::task::Poll::Ready(Some(res)),
                std::task::Poll::Pending => std::task::Poll::Ready(None),
            })
            .await;
            assert!(
                completed.is_none(),
                "frame is incomplete, read must not finish"
            );
        }

        peer.write_all(&wire[4..]).await.unwrap();
        peer.flush().await.unwrap();

        assert_eq!(reader.read_frame().await.unwrap(), frame);
    }

    #[tokio::test]
    async fn frame_reader_losing_a_select_race_keeps_partial_frame() {
        let (mut peer, carrier) = tokio::io::duplex(128);
        let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"payload")).unwrap();
        let wire = frame.encode().unwrap();
        let mut reader = FrameReader::new(carrier, FrameLimits::default());

        peer.write_all(&wire[..5]).await.unwrap();
        peer.flush().await.unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<u8>(1);
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(1).await;
        });
        let lost_race = tokio::select! {
            biased;
            _ = reader.read_frame() => false,
            _ = rx.recv() => true,
        };
        assert!(lost_race, "the competing branch should win while mid-frame");

        peer.write_all(&wire[5..]).await.unwrap();
        peer.flush().await.unwrap();

        assert_eq!(reader.read_frame().await.unwrap(), frame);
    }

    #[tokio::test]
    async fn frame_reader_reports_closed_on_clean_eof() {
        let (peer, carrier) = tokio::io::duplex(64);
        drop(peer);
        let mut reader = FrameReader::new(carrier, FrameLimits::default());

        assert!(matches!(
            reader.read_frame().await.unwrap_err(),
            FrameIoError::Closed
        ));
    }

    #[tokio::test]
    async fn frame_reader_reports_truncated_on_eof_mid_frame() {
        let (mut peer, carrier) = tokio::io::duplex(64);
        peer.write_all(&[0x01, 0x11, 0x00, 0x00, 0x01, 0x03, b'a'])
            .await
            .unwrap();
        drop(peer);
        let mut reader = FrameReader::new(carrier, FrameLimits::default());

        assert!(matches!(
            reader.read_frame().await.unwrap_err(),
            FrameIoError::Protocol(ProtocolError::Truncated)
        ));
    }

    #[tokio::test]
    async fn frame_reader_rejects_oversized_frame() {
        let (mut peer, carrier) = tokio::io::duplex(64);
        peer.write_all(&[0x01, 0x11, 0x00, 0x00, 0x01, 0x03, b'a', b'b', b'c'])
            .await
            .unwrap();
        let mut reader = FrameReader::new(carrier, FrameLimits { max_frame_size: 2 });

        assert!(matches!(
            reader.read_frame().await.unwrap_err(),
            FrameIoError::Protocol(ProtocolError::OversizedFrame {
                length: 3,
                limit: 2
            })
        ));
    }

    #[tokio::test]
    async fn frame_reader_rejects_bad_version_without_hanging() {
        let (mut peer, carrier) = tokio::io::duplex(64);
        peer.write_all(&[0x09, 0x11, 0x00, 0x00, 0x01, 0x00])
            .await
            .unwrap();
        let mut reader = FrameReader::new(carrier, FrameLimits::default());

        assert!(matches!(
            reader.read_frame().await.unwrap_err(),
            FrameIoError::Protocol(ProtocolError::UnsupportedVersion(9))
        ));
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
        assert!(written.is_empty(), "expected no bytes written");
    }

    #[tokio::test]
    async fn write_frames_coalesces_multiple_frames() {
        let (mut writer, reader) = tokio::io::duplex(256);
        let frame1 = Frame::new(FrameType::Ping, 0, 0, Bytes::from_static(b"1234")).unwrap();
        let frame2 = Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"hello")).unwrap();
        let frame3 = Frame::new(FrameType::TcpClose, 0, 1, Bytes::from_static(&[0x00])).unwrap();

        write_frames(
            &mut writer,
            &[frame1.clone(), frame2.clone(), frame3.clone()],
        )
        .await
        .unwrap();
        drop(writer);

        let mut read_frames = Vec::new();
        let mut frame_reader = FrameReader::new(reader, FrameLimits::default());
        while let Ok(frame) = frame_reader.read_frame().await {
            read_frames.push(frame);
        }

        assert_eq!(read_frames.len(), 3);
        assert_eq!(read_frames[0], frame1);
        assert_eq!(read_frames[1], frame2);
        assert_eq!(read_frames[2], frame3);
    }

    #[tokio::test]
    async fn write_frames_empty_does_not_write() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        write_frames(&mut writer, &[] as &[Frame]).await.unwrap();
        drop(writer);

        let mut written = Vec::new();
        reader.read_to_end(&mut written).await.unwrap();
        assert!(written.is_empty(), "expected no bytes written");
    }

    #[tokio::test]
    async fn read_frame_rejects_unsupported_version_early() {
        let (mut peer, mut carrier) = tokio::io::duplex(64);
        peer.write_all(&[0x02, 0x11, 0x00, 0x00]).await.unwrap();
        let err = read_frame(&mut carrier, FrameLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FrameIoError::Protocol(ProtocolError::UnsupportedVersion(2))
        ));
    }

    #[tokio::test]
    async fn read_frame_rejects_invalid_frame_type_early() {
        let (mut peer, mut carrier) = tokio::io::duplex(64);
        peer.write_all(&[0x01, 0x00, 0x00, 0x00]).await.unwrap();
        let err = read_frame(&mut carrier, FrameLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FrameIoError::Protocol(ProtocolError::UnknownFrameType(0))
        ));
    }

    #[tokio::test]
    async fn read_frame_rejects_invalid_flags_early() {
        let (mut peer, mut carrier) = tokio::io::duplex(64);
        peer.write_all(&[0x01, 0x11, 0x01, 0x00]).await.unwrap();
        let err = read_frame(&mut carrier, FrameLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FrameIoError::Protocol(ProtocolError::UnsupportedFlag(0x0100))
        ));
    }
}
