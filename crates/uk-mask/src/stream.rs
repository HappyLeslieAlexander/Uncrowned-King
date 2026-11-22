//! ChaCha20 keystream wrapper for masked TCP streams.
//!
//! Both stream directions run an independent ChaCha20 keystream (client→server
//! and server→client keys derived per credential; both keyed with the one
//! client-generated nonce sent after the prelude). This is masking only: TLS
//! above the wrapper provides all confidentiality and integrity that matters.
//!
//! # Partial-write safety
//!
//! The wrapper never retains ciphertext across `poll_write` calls: it encrypts
//! at most [`MAX_WRITE_CHUNK`] bytes into an internal scratch buffer, hands
//! them to the inner stream, and — whenever the inner write accepts fewer
//! bytes than were encrypted, errors, or returns pending — rewinds the
//! keystream to the confirmed offset with `try_seek`. A caller is free to
//! resubmit different plaintext after any non-complete result without
//! corrupting the stream.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use chacha20::{
    ChaCha20, Key, KeyIvInit, Nonce,
    cipher::{StreamCipher, StreamCipherSeek},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{MaskError, MaskKeys, NONCE_LEN, STREAM_LIMIT};

/// Upper bound on plaintext encrypted per `poll_write` call; bounds the
/// scratch buffer and keeps rewind work tiny.
pub const MAX_WRITE_CHUNK: usize = 64 * 1024;

struct Direction {
    cipher: ChaCha20,
    offset: u64,
}

impl Direction {
    fn new(key: [u8; 32], nonce: &[u8; NONCE_LEN]) -> Self {
        Self {
            cipher: ChaCha20::new(&Key::from(key), &Nonce::from(*nonce)),
            offset: 0,
        }
    }

    fn rewind(&mut self) -> io::Result<()> {
        self.cipher
            .try_seek(self.offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "keystream seek failed"))
    }
}

/// An `AsyncRead + AsyncWrite` wrapper masking both directions of `S` with the
/// per-credential keystreams.
pub struct MaskedStream<S> {
    inner: S,
    read: Direction,
    write: Direction,
    scratch: Vec<u8>,
}

impl<S> MaskedStream<S> {
    /// Wraps the client side: writes with the c2s key, reads with s2c.
    pub fn new_client(inner: S, keys: &MaskKeys, nonce: &[u8; NONCE_LEN]) -> Self {
        Self::new(inner, keys.c2s(), keys.s2c(), nonce)
    }

    /// Wraps the server side: writes with the s2c key, reads with c2s.
    pub fn new_server(inner: S, keys: &MaskKeys, nonce: &[u8; NONCE_LEN]) -> Self {
        Self::new(inner, keys.s2c(), keys.c2s(), nonce)
    }

    fn new(inner: S, write_key: [u8; 32], read_key: [u8; 32], nonce: &[u8; NONCE_LEN]) -> Self {
        Self {
            inner,
            read: Direction::new(read_key, nonce),
            write: Direction::new(write_key, nonce),
            scratch: Vec::new(),
        }
    }

    /// Returns the wrapped stream, dropping keystream state.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Bytes masked so far on the read direction.
    #[cfg(test)]
    pub(crate) const fn read_offset(&self) -> u64 {
        self.read.offset
    }

    /// Bytes masked so far on the write direction.
    #[cfg(test)]
    pub(crate) const fn write_offset(&self) -> u64 {
        self.write.offset
    }
}

impl<S> std::fmt::Debug for MaskedStream<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MaskedStream")
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MaskedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let read = buf.filled().len() - filled_before;
        if read > 0 {
            this.read.offset = this
                .read
                .offset
                .checked_add(read as u64)
                .filter(|offset| *offset <= STREAM_LIMIT)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, MaskError::StreamLimitExceeded)
                })?;
            let filled = buf.filled_mut();
            this.read
                .cipher
                .try_apply_keystream(&mut filled[filled_before..])
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, MaskError::StreamLimitExceeded)
                })?;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MaskedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MAX_WRITE_CHUNK);
        this.write.offset = this
            .write
            .offset
            .checked_add(take as u64)
            .filter(|offset| *offset <= STREAM_LIMIT)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, MaskError::StreamLimitExceeded)
            })?;
        // Reset to the confirmed offset before adding `take`: every
        // non-complete outcome below rewinds to the bytes actually accepted.
        this.write.offset -= take as u64;
        this.scratch.clear();
        this.scratch.extend_from_slice(&buf[..take]);
        this.write
            .cipher
            .try_apply_keystream(&mut this.scratch)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, MaskError::StreamLimitExceeded)
            })?;
        match Pin::new(&mut this.inner).poll_write(cx, &this.scratch) {
            Poll::Ready(Ok(written)) if written == take => {
                this.write.offset += take as u64;
                Poll::Ready(Ok(take))
            }
            Poll::Ready(Ok(written)) => {
                if written == 0 {
                    this.write.rewind()?;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "masked inner stream wrote zero bytes",
                    )));
                }
                this.write.offset += written as u64;
                this.write.rewind()?;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => {
                this.write.rewind()?;
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                this.write.rewind()?;
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use chacha20::cipher::StreamCipher;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::{MaskKeys, STREAM_LIMIT};

    fn keys() -> MaskKeys {
        MaskKeys::derive(b"test-key-id", b"0123456789abcdef0123456789abcdef")
    }

    fn nonce() -> [u8; NONCE_LEN] {
        [7; NONCE_LEN]
    }

    #[tokio::test]
    async fn echo_round_trip_with_random_chunks() {
        let mut rng = StdRng::seed_from_u64(42);
        let keys = keys();
        let nonce = nonce();
        let (client_side, server_side) = duplex(64 * 1024);
        let mut client = MaskedStream::new_client(client_side, &keys, &nonce);
        let mut server = MaskedStream::new_server(server_side, &keys, &nonce);

        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let expected_len = payload.len();
        let writer = tokio::spawn(async move {
            let mut offset = 0;
            while offset < payload.len() {
                let chunk = rng.gen_range(1..=3000_usize).min(payload.len() - offset);
                client
                    .write_all(&payload[offset..offset + chunk])
                    .await
                    .unwrap();
                offset += chunk;
            }
            client.flush().await.unwrap();
            client
        });

        let mut received = Vec::new();
        let mut remaining = expected_len;
        while remaining > 0 {
            let mut piece = vec![0u8; 1];
            let read = server.read(&mut piece).await.unwrap();
            assert!(read > 0);
            received.extend_from_slice(&piece[..read]);
            remaining -= read;
        }
        let mut client = writer.await.unwrap();
        assert_eq!(received.len(), expected_len);
        client.shutdown().await.unwrap();
        // All bytes flowed masked; write offset advanced by exactly the payload.
        assert_eq!(client.write_offset() as usize, expected_len);
        assert_eq!(server.read_offset() as usize, expected_len);
    }

    #[tokio::test]
    async fn partial_writes_rollback_keystream() {
        // A 512-byte duplex forces write_all to loop over partial accepts.
        let keys = keys();
        let nonce = nonce();
        let (client_side, server_side) = duplex(512);
        let mut client = MaskedStream::new_client(client_side, &keys, &nonce);
        let mut server = MaskedStream::new_server(server_side, &keys, &nonce);

        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 249) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move { client.write_all(&payload).await.unwrap() });

        let mut received = Vec::new();
        while received.len() < expected.len() {
            let mut piece = [0u8; 97];
            let read = server.read(&mut piece).await.unwrap();
            assert!(read > 0);
            received.extend_from_slice(&piece[..read]);
        }
        writer.await.unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn direction_keys_are_independent() {
        let keys = keys();
        let nonce = nonce();
        let (a, b) = duplex(1024);
        let mut client = MaskedStream::new_client(a, &keys, &nonce);
        // Server side wrapped with swapped construction must not decrypt.
        let mut wrong = MaskedStream::new_client(b, &keys, &nonce);
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        wrong.read_exact(&mut buf).await.unwrap();
        assert_ne!(&buf, b"hello");
    }

    #[tokio::test]
    async fn write_beyond_stream_limit_fails() {
        let keys = keys();
        let nonce = nonce();
        let (client_side, _server_side) = duplex(1024);
        let mut client = MaskedStream::new_client(client_side, &keys, &nonce);
        client.write.offset = STREAM_LIMIT;
        let err = client.write(b"x").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_beyond_stream_limit_fails() {
        let keys = keys();
        let nonce = nonce();
        let (client_side, mut server_side) = duplex(1024);
        let mut client = MaskedStream::new_client(client_side, &keys, &nonce);
        client.read.offset = STREAM_LIMIT;
        server_side.write_all(b"xy").await.unwrap();
        let err = client.read(&mut [0u8; 2]).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn wrapper_ciphertext_matches_fresh_cipher() {
        // The wrapper's output must equal a fresh ChaCha20 keystream over the
        // same plaintext with the c2s key — and reading the raw duplex side
        // (no server wrapper) exposes exactly the on-wire ciphertext.
        let keys = keys();
        let nonce = nonce();
        let mut reference = ChaCha20::new(&Key::from(keys.c2s()), &Nonce::from(nonce));
        let plaintext: Vec<u8> = (0..1000u32).map(|i| (i % 253) as u8).collect();
        let mut expected = plaintext.clone();
        reference.try_apply_keystream(&mut expected).unwrap();

        let (client_side, mut raw_side) = duplex(64 * 1024);
        let mut client = MaskedStream::new_client(client_side, &keys, &nonce);
        let writer = tokio::spawn(async move { client.write_all(&plaintext).await.unwrap() });
        let mut raw = vec![0u8; expected.len()];
        raw_side.read_exact(&mut raw).await.unwrap();
        writer.await.unwrap();
        assert_eq!(raw, expected);
    }
}
