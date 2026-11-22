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

use crate::{ClientPrelude, MaskError, MaskKeys, NONCE_LEN, PRELUDE_LEN, STREAM_LIMIT};

/// Upper bound on plaintext encrypted per `poll_write` call; bounds the
/// scratch buffer and keeps rewind work tiny.
pub const MAX_WRITE_CHUNK: usize = 64 * 1024;

const PRELUDE_WIRE_LEN: usize = PRELUDE_LEN + NONCE_LEN;

fn stream_limit_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, MaskError::StreamLimitExceeded)
}

/// Readiness probe checked before encrypting a chunk in [`MaskedStream`].
pub trait WriteReady {
    /// Polls whether the underlying sink is ready to accept writes.
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl WriteReady for tokio::net::TcpStream {
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Self::poll_write_ready(self, cx)
    }
}

impl WriteReady for tokio::io::DuplexStream {
    fn poll_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl WriteReady for tokio::io::SimplexStream {
    fn poll_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl WriteReady for tokio::io::WriteHalf<tokio::io::SimplexStream> {
    fn poll_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

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

struct PendingPrelude {
    bytes: [u8; PRELUDE_WIRE_LEN],
    sent: usize,
}

/// An `AsyncRead + AsyncWrite` wrapper masking both directions of `S` with the
/// per-credential keystreams.
pub struct MaskedStream<S> {
    inner: S,
    read: Direction,
    write: Direction,
    scratch: Vec<u8>,
    pending_prelude: Option<PendingPrelude>,
}

impl<S> MaskedStream<S> {
    /// Wraps the client side: writes with the c2s key, reads with s2c.
    pub fn new_client(inner: S, keys: &MaskKeys, nonce: &[u8; NONCE_LEN]) -> Self {
        Self::new(inner, keys.c2s(), keys.s2c(), nonce)
    }

    /// Wraps the client side and buffers `prelude` and its nonce to coalesce
    /// them with the first encrypted write.
    pub fn new_client_with_prelude(inner: S, keys: &MaskKeys, prelude: &ClientPrelude) -> Self {
        let mut bytes = [0_u8; PRELUDE_WIRE_LEN];
        bytes[..PRELUDE_LEN].copy_from_slice(&prelude.bytes);
        bytes[PRELUDE_LEN..].copy_from_slice(&prelude.nonce);
        Self {
            inner,
            read: Direction::new(keys.s2c(), &prelude.nonce),
            write: Direction::new(keys.c2s(), &prelude.nonce),
            scratch: Vec::new(),
            pending_prelude: Some(PendingPrelude { bytes, sent: 0 }),
        }
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
            pending_prelude: None,
        }
    }

    /// Returns a shared reference to the wrapped stream.
    pub const fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped stream.
    pub const fn get_mut(&mut self) -> &mut S {
        &mut self.inner
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
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let remaining = STREAM_LIMIT.saturating_sub(this.read.offset);
        if remaining == 0 {
            return Poll::Ready(Err(stream_limit_error()));
        }
        let allowed = usize::try_from(remaining.min(buf.remaining() as u64))
            .expect("allowed read length is bounded by buf.remaining()");
        let unfilled = buf.initialize_unfilled_to(allowed);
        let mut inner_buf = ReadBuf::new(unfilled);
        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut inner_buf))?;
        let count = inner_buf.filled().len();
        if count > 0 {
            this.read
                .cipher
                .try_apply_keystream(&mut inner_buf.filled_mut()[..count])
                .map_err(|_| stream_limit_error())?;
            this.read.offset += count as u64;
            buf.advance(count);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + WriteReady + Unpin> AsyncWrite for MaskedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let remaining = STREAM_LIMIT.saturating_sub(this.write.offset);
        if remaining == 0 {
            return Poll::Ready(Err(stream_limit_error()));
        }
        loop {
            ready!(this.inner.poll_write_ready(cx))?;
            let head_len = this
                .pending_prelude
                .as_ref()
                .map_or(0, |pending| PRELUDE_WIRE_LEN - pending.sent);
            let take = usize::try_from(remaining.min(buf.len() as u64).min(MAX_WRITE_CHUNK as u64))
                .expect("chunk size is bounded by MAX_WRITE_CHUNK");
            let total = head_len + take;
            if this.scratch.len() < total {
                this.scratch.resize(total, 0);
            }
            if let Some(pending) = &this.pending_prelude {
                this.scratch[..head_len].copy_from_slice(&pending.bytes[pending.sent..]);
            }
            this.write
                .cipher
                .try_apply_keystream_b2b(&buf[..take], &mut this.scratch[head_len..total])
                .map_err(|_| stream_limit_error())?;
            match Pin::new(&mut this.inner).poll_write(cx, &this.scratch[..total]) {
                Poll::Pending => {
                    this.write.rewind()?;
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    this.write.rewind()?;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(0)) => {
                    this.write.rewind()?;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "masked inner stream wrote zero bytes",
                    )));
                }
                Poll::Ready(Ok(written)) if written <= head_len => {
                    this.write.rewind()?;
                    if let Some(pending) = &mut this.pending_prelude {
                        pending.sent += written;
                        if pending.sent >= PRELUDE_WIRE_LEN {
                            this.pending_prelude = None;
                        }
                    }
                }
                Poll::Ready(Ok(written)) => {
                    this.pending_prelude = None;
                    let cipher_written = (written - head_len).min(take);
                    this.write.offset += cipher_written as u64;
                    if cipher_written < take {
                        this.write.rewind()?;
                    }
                    return Poll::Ready(Ok(cipher_written));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while let Some(pending) = this.pending_prelude.as_mut() {
            ready!(this.inner.poll_write_ready(cx))?;
            let written =
                ready!(Pin::new(&mut this.inner).poll_write(cx, &pending.bytes[pending.sent..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "masked inner stream wrote zero bytes while flushing prelude",
                )));
            }
            pending.sent += written;
            if pending.sent >= PRELUDE_WIRE_LEN {
                this.pending_prelude = None;
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
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

    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Waker;

    use chacha20::cipher::StreamCipherSeek;

    fn apply_at(key: &[u8; 32], nonce: &[u8; NONCE_LEN], offset: u64, bytes: &mut [u8]) {
        let mut cipher = ChaCha20::new(&Key::from(*key), &Nonce::from(*nonce));
        cipher.try_seek(offset).unwrap();
        cipher.try_apply_keystream(bytes).unwrap();
    }

    #[test]
    fn empty_io_is_immediately_ready() {
        let keys = keys();
        let (_client_side, server_side) = duplex(64);
        let mut server = MaskedStream::new_server(server_side, &keys, &nonce());
        server.read.offset = STREAM_LIMIT;
        server.write.offset = STREAM_LIMIT;

        let mut context = Context::from_waker(Waker::noop());
        let mut empty = [];
        let mut read_buf = ReadBuf::new(&mut empty);
        assert!(matches!(
            Pin::new(&mut server).poll_read(&mut context, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut server).poll_write(&mut context, &[]),
            Poll::Ready(Ok(0))
        ));
    }

    #[tokio::test]
    async fn limits_clamp_final_bytes_and_preserve_readbuf_prefix() {
        let keys = keys();
        let nonce = nonce();
        let (client_side, mut peer) = duplex(64);
        let mut client = MaskedStream::new_client(client_side, &keys, &nonce);

        client.write.offset = STREAM_LIMIT - 3;
        client.write.cipher.try_seek(STREAM_LIMIT - 3).unwrap();
        client.read.offset = STREAM_LIMIT - 5;
        client.read.cipher.try_seek(STREAM_LIMIT - 5).unwrap();

        // Final 3 write bytes succeed even though input is 7 bytes; next write fails.
        assert_eq!(client.write(b"request").await.unwrap(), 3);
        let mut wire = [0_u8; 3];
        peer.read_exact(&mut wire).await.unwrap();
        apply_at(&keys.c2s(), &nonce, STREAM_LIMIT - 3, &mut wire);
        assert_eq!(&wire, b"req");
        assert_eq!(
            client.write(b"x").await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(client.write(&[]).await.unwrap(), 0);

        // Pre-filled prefix in ReadBuf must remain untouched while clamping at STREAM_LIMIT.
        let mut response = *b"reply";
        apply_at(&keys.s2c(), &nonce, STREAM_LIMIT - 5, &mut response);
        peer.write_all(&response).await.unwrap();
        peer.write_all(b"XX").await.unwrap();

        let mut backing = [0xa5_u8; 16];
        let mut read_buf = ReadBuf::new(&mut backing);
        read_buf.put_slice(b"head");
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut client).poll_read(&mut context, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf.filled(), b"headreply");
        assert_eq!(
            client.read(&mut [0_u8; 2]).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(client.read(&mut []).await.unwrap(), 0);
    }

    #[derive(Debug)]
    enum WriteOutcome {
        Accept(usize),
        Pending,
        Error(ErrorKind),
    }

    #[derive(Debug)]
    struct PendingWriteStream {
        ready: Arc<AtomicBool>,
        writes: Arc<AtomicUsize>,
        written: Arc<std::sync::Mutex<Vec<u8>>>,
        outcomes: std::sync::Mutex<VecDeque<WriteOutcome>>,
    }

    impl AsyncRead for PendingWriteStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingWriteStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            let outcome = self.outcomes.lock().unwrap().pop_front();
            match outcome.unwrap_or(WriteOutcome::Accept(input.len())) {
                WriteOutcome::Accept(limit) => {
                    let count = input.len().min(limit);
                    self.written
                        .lock()
                        .unwrap()
                        .extend_from_slice(&input[..count]);
                    Poll::Ready(Ok(count))
                }
                WriteOutcome::Pending => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                WriteOutcome::Error(kind) => Poll::Ready(Err(kind.into())),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl WriteReady for PendingWriteStream {
        fn poll_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.ready.load(Ordering::Relaxed) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn waits_for_write_ready_before_encrypting_or_allocating() {
        let ready = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicUsize::new(0));
        let written = Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner = PendingWriteStream {
            ready: Arc::clone(&ready),
            writes: Arc::clone(&writes),
            written: Arc::clone(&written),
            outcomes: std::sync::Mutex::default(),
        };
        let keys = keys();
        let nonce = nonce();
        let mut client = MaskedStream::new_client(inner, &keys, &nonce);
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut context, b"initial"),
            Poll::Pending
        ));
        assert_eq!(writes.load(Ordering::Relaxed), 0);
        assert!(client.scratch.is_empty());

        ready.store(true, Ordering::Relaxed);
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut context, b"changed"),
            Poll::Ready(Ok(7))
        ));
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        let mut payload = written.lock().unwrap().clone();
        apply_at(&keys.c2s(), &nonce, 0, &mut payload);
        assert_eq!(&payload, b"changed");
    }

    #[test]
    fn retries_changed_input_after_short_write_pending_writezero_and_error() {
        let written = Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner = PendingWriteStream {
            ready: Arc::new(AtomicBool::new(true)),
            writes: Arc::new(AtomicUsize::new(0)),
            written: Arc::clone(&written),
            outcomes: std::sync::Mutex::new(VecDeque::from([
                WriteOutcome::Accept(3),
                WriteOutcome::Pending,
                WriteOutcome::Error(ErrorKind::Interrupted),
                WriteOutcome::Accept(0),
                WriteOutcome::Accept(usize::MAX),
            ])),
        };
        let keys = keys();
        let nonce = nonce();
        let mut client = MaskedStream::new_client(inner, &keys, &nonce);
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut context, b"abc-unaccepted"),
            Poll::Ready(Ok(3))
        ));
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut context, b"pending input"),
            Poll::Pending
        ));
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut context, b"error input"),
            Poll::Ready(Err(err)) if err.kind() == ErrorKind::Interrupted
        ));
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut context, b"writezero"),
            Poll::Ready(Err(err)) if err.kind() == ErrorKind::WriteZero
        ));
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut context, b"z"),
            Poll::Ready(Ok(1))
        ));
        let mut payload = written.lock().unwrap().clone();
        apply_at(&keys.c2s(), &nonce, 0, &mut payload);
        assert_eq!(&payload, b"abcz");
    }

    #[tokio::test]
    async fn client_with_prelude_coalesces_into_single_write() {
        use crate::{PreludePolicy, verify_prelude};
        use tokio::io::simplex;

        let keys = keys();
        let mut prng = StdRng::seed_from_u64(99);
        let prelude = keys
            .encode_prelude(PreludePolicy::Fade, &mut prng, 0x42, 7)
            .unwrap();

        // 1. Single-write coalescing of 76B prelude+nonce + encrypted payload.
        let writes = Arc::new(AtomicUsize::new(0));
        let written = Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner = PendingWriteStream {
            ready: Arc::new(AtomicBool::new(true)),
            writes: Arc::clone(&writes),
            written: Arc::clone(&written),
            outcomes: std::sync::Mutex::default(),
        };
        let mut client = MaskedStream::new_client_with_prelude(inner, &keys, &prelude);
        client.write_all(b"ClientHello").await.unwrap();
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        {
            let wire = written.lock().unwrap();
            assert_eq!(wire.len(), PRELUDE_WIRE_LEN + b"ClientHello".len());
            assert_eq!(&wire[..PRELUDE_LEN], &prelude.bytes);
            assert_eq!(&wire[PRELUDE_LEN..PRELUDE_WIRE_LEN], &prelude.nonce);
            let mut decrypted = wire[PRELUDE_WIRE_LEN..].to_vec();
            apply_at(&keys.c2s(), &prelude.nonce, 0, &mut decrypted);
            assert_eq!(&decrypted, b"ClientHello");
        }

        // 2. Partial writes across prelude boundary.
        let written_partial = Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner_partial = PendingWriteStream {
            ready: Arc::new(AtomicBool::new(true)),
            writes: Arc::new(AtomicUsize::new(0)),
            written: Arc::clone(&written_partial),
            outcomes: std::sync::Mutex::new(VecDeque::from([
                WriteOutcome::Accept(20),
                WriteOutcome::Pending,
                WriteOutcome::Accept(56),
                WriteOutcome::Pending,
                WriteOutcome::Accept(3),
                WriteOutcome::Accept(usize::MAX),
            ])),
        };
        let mut partial_client =
            MaskedStream::new_client_with_prelude(inner_partial, &keys, &prelude);
        partial_client.write_all(b"hello-world").await.unwrap();
        {
            let wire = written_partial.lock().unwrap();
            assert_eq!(wire.len(), PRELUDE_WIRE_LEN + b"hello-world".len());
            assert_eq!(&wire[..PRELUDE_LEN], &prelude.bytes);
            assert_eq!(&wire[PRELUDE_LEN..PRELUDE_WIRE_LEN], &prelude.nonce);
            let mut decrypted = wire[PRELUDE_WIRE_LEN..].to_vec();
            apply_at(&keys.c2s(), &prelude.nonce, 0, &mut decrypted);
            assert_eq!(&decrypted, b"hello-world");
        }

        // 3. `flush()` drains pending prelude when no payload write occurred yet.
        let written_flush = Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner_flush = PendingWriteStream {
            ready: Arc::new(AtomicBool::new(true)),
            writes: Arc::new(AtomicUsize::new(0)),
            written: Arc::clone(&written_flush),
            outcomes: std::sync::Mutex::new(VecDeque::from([
                WriteOutcome::Accept(30),
                WriteOutcome::Accept(46),
            ])),
        };
        let mut flush_client = MaskedStream::new_client_with_prelude(inner_flush, &keys, &prelude);
        flush_client.flush().await.unwrap();
        {
            let wire = written_flush.lock().unwrap();
            assert_eq!(wire.len(), PRELUDE_WIRE_LEN);
            assert_eq!(&wire[..PRELUDE_LEN], &prelude.bytes);
            assert_eq!(&wire[PRELUDE_LEN..PRELUDE_WIRE_LEN], &prelude.nonce);
        }

        // 4. End-to-end SimplexStream + get_ref/get_mut + server prelude verification.
        let (mut simplex_rx, simplex_tx) = simplex(4096);
        let mut simplex_client = MaskedStream::new_client_with_prelude(simplex_tx, &keys, &prelude);
        let _tx_ref = simplex_client.get_ref();
        let _tx_mut = simplex_client.get_mut();
        simplex_client.write_all(b"ping").await.unwrap();
        simplex_client.flush().await.unwrap();

        let mut head = [0_u8; PRELUDE_WIRE_LEN];
        simplex_rx.read_exact(&mut head).await.unwrap();
        let rx_prelude: [u8; PRELUDE_LEN] = head[..PRELUDE_LEN].try_into().unwrap();
        let rx_nonce: [u8; NONCE_LEN] = head[PRELUDE_LEN..].try_into().unwrap();
        let key_set = [keys];
        let (matched_keys, auth) = verify_prelude(&key_set, &rx_prelude, &rx_nonce).unwrap();
        assert_eq!(auth.identity, 0x42);
        assert_eq!(auth.counter, 7);

        let mut server = MaskedStream::new_server(simplex_rx, matched_keys, &rx_nonce);
        let mut buf = [0_u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn client_with_prelude_partial_write_spanning_head_and_payload_rewinds_and_caps_chunk() {
        use crate::PreludePolicy;
        let keys = keys();
        let mut prng = StdRng::seed_from_u64(101);
        let prelude = keys
            .encode_prelude(PreludePolicy::Fade, &mut prng, 0x99, 11)
            .unwrap();

        // 1. Single poll_write accepts `head_len < written < total` (finishes 76B
        // prelude AND partially writes encrypted payload, requiring keystream rewind).
        let written_span = Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner_span = PendingWriteStream {
            ready: Arc::new(AtomicBool::new(true)),
            writes: Arc::new(AtomicUsize::new(0)),
            written: Arc::clone(&written_span),
            outcomes: std::sync::Mutex::new(VecDeque::from([
                WriteOutcome::Accept(PRELUDE_WIRE_LEN + 5),
                WriteOutcome::Accept(usize::MAX),
            ])),
        };
        let mut span_client = MaskedStream::new_client_with_prelude(inner_span, &keys, &prelude);
        span_client.write_all(b"hello-world").await.unwrap();
        assert_eq!(span_client.write_offset(), 11);
        {
            let wire = written_span.lock().unwrap();
            assert_eq!(wire.len(), PRELUDE_WIRE_LEN + b"hello-world".len());
            assert_eq!(&wire[..PRELUDE_LEN], &prelude.bytes);
            assert_eq!(&wire[PRELUDE_LEN..PRELUDE_WIRE_LEN], &prelude.nonce);
            let mut decrypted = wire[PRELUDE_WIRE_LEN..].to_vec();
            apply_at(&keys.c2s(), &prelude.nonce, 0, &mut decrypted);
            assert_eq!(&decrypted, b"hello-world");
        }

        // 2. Payload exceeding MAX_WRITE_CHUNK while pending_prelude is Some:
        // first inner write is capped at PRELUDE_WIRE_LEN + MAX_WRITE_CHUNK.
        let writes_large = Arc::new(AtomicUsize::new(0));
        let written_large = Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner_large = PendingWriteStream {
            ready: Arc::new(AtomicBool::new(true)),
            writes: Arc::clone(&writes_large),
            written: Arc::clone(&written_large),
            outcomes: std::sync::Mutex::default(),
        };
        let mut large_client = MaskedStream::new_client_with_prelude(inner_large, &keys, &prelude);
        let large: Vec<u8> = (0..(MAX_WRITE_CHUNK + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        large_client.write_all(&large).await.unwrap();
        assert_eq!(writes_large.load(Ordering::Relaxed), 2);
        assert_eq!(large_client.write_offset(), large.len() as u64);
        {
            let wire = written_large.lock().unwrap();
            assert_eq!(wire.len(), PRELUDE_WIRE_LEN + large.len());
            assert_eq!(&wire[..PRELUDE_LEN], &prelude.bytes);
            assert_eq!(&wire[PRELUDE_LEN..PRELUDE_WIRE_LEN], &prelude.nonce);
            let mut decrypted = wire[PRELUDE_WIRE_LEN..].to_vec();
            apply_at(&keys.c2s(), &prelude.nonce, 0, &mut decrypted);
            assert_eq!(decrypted, large);
        }
    }
}
