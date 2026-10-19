#![no_main]

//! Fuzzes incremental frame reading through `FrameReader`.
//!
//! The input is fed in adversarially sized chunks (chunk boundaries are
//! derived from the input bytes themselves, so the fuzzer explores split
//! points). Two properties are checked:
//!
//! 1. `FrameReader` never panics, however the input is split.
//! 2. Chunked incremental decoding produces exactly the same frame sequence
//!    as one-shot `Frame::decode` over the whole input (differential check).

use std::io;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll};

use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, ReadBuf};
use uk_proto::{Frame, FrameLimits, FrameReader};

/// In-memory reader that yields its input in chunks. The next chunk size is
/// derived from the byte at the current position (`1 + (byte % 32)`), so the
/// fuzzer controls split points by mutating content bytes. Deterministic for
/// a given input; never yields empty chunks while data remains.
struct ChunkReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl AsyncRead for ChunkReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos >= self.data.len() {
            // End of input: report EOF.
            return Poll::Ready(Ok(()));
        }
        let chunk = 1 + (self.data[self.pos] as usize % 32);
        let end = (self.pos + chunk)
            .min(self.data.len())
            .min(self.pos + buf.remaining());
        let n = end - self.pos;
        buf.put_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("fuzz tokio runtime builds")
});

fuzz_target!(|data: &[u8]| {
    let limits = FrameLimits {
        max_frame_size: 65_536,
    };

    // Incrementally decode through chunked feeding.
    let mut chunked_frames = Vec::new();
    RUNTIME.block_on(async {
        let reader = ChunkReader { data, pos: 0 };
        let mut frame_reader = FrameReader::new(reader, limits);
        loop {
            match frame_reader.read_frame().await {
                Ok(frame) => chunked_frames.push(frame),
                // Closed, truncated, or a decode error: stop. Calling
                // read_frame again after a decode error would return the
                // same error forever since the buffer is untouched.
                Err(_) => break,
            }
        }
    });

    // One-shot decode of the same bytes for comparison.
    let mut oneshot_frames = Vec::new();
    let mut rest = data;
    loop {
        match Frame::decode(&mut rest, limits) {
            Ok(frame) => oneshot_frames.push(frame),
            Err(_) => break,
        }
    }

    assert_eq!(chunked_frames, oneshot_frames);
});
