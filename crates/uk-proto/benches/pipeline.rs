//! Throughput micro-benchmarks for the relay data plane.
//!
//! These push frames through an in-memory duplex the way the relay does:
//! encode on the write side, decode on the read side. They bound the
//! protocol's per-byte CPU overhead independent of real network syscalls.
//! Run with `cargo bench -p uk-proto --bench pipeline`.

// criterion_group! expands to an undocumented public function.
#![allow(missing_docs)]

use std::hint::black_box;

use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use uk_proto::{Frame, FrameLimits, FrameType, read_frame, write_frame, write_frames};

const FRAME_LIMITS: FrameLimits = FrameLimits {
    max_frame_size: 65_536,
};

const CHUNK: usize = 65_536;
const CHUNKS: usize = 16;
const TOTAL: u64 = (CHUNK * CHUNKS) as u64;

fn data_frame() -> Frame {
    Frame::new(FrameType::TcpData, 0, 1, Bytes::from(vec![0x5a_u8; CHUNK])).unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Encode 16 x 64 KiB frames, pump them through a duplex, decode on the far
/// side. Models one direction of a bulk relay transfer.
fn bench_duplex_pipeline(c: &mut Criterion) {
    let rt = runtime();
    let frame = data_frame();
    let mut group = c.benchmark_group("pipeline");
    group.throughput(Throughput::Bytes(TOTAL));
    group.bench_function("frame_duplex_1mb", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut writer, mut reader) = tokio::io::duplex(4 * 1024 * 1024);
                let read_task = tokio::spawn(async move {
                    let mut total = 0usize;
                    for _ in 0..CHUNKS {
                        let f = read_frame(&mut reader, FRAME_LIMITS).await.unwrap();
                        total += f.payload.len();
                    }
                    total
                });
                for _ in 0..CHUNKS {
                    write_frame(&mut writer, black_box(&frame)).await.unwrap();
                }
                drop(writer);
                black_box(read_task.await.unwrap())
            })
        });
    });
    group.finish();
}

/// Compare per-frame writes against the coalescing `write_frames` batch API.
fn bench_write_coalescing(c: &mut Criterion) {
    let rt = runtime();
    let frames: Vec<Frame> = (0..CHUNKS).map(|_| data_frame()).collect();
    let refs: Vec<&Frame> = frames.iter().collect();
    let mut group = c.benchmark_group("pipeline");
    group.throughput(Throughput::Bytes(TOTAL));
    group.bench_function("write_single_frames_1mb", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut writer, mut reader) = tokio::io::duplex(4 * 1024 * 1024);
                let read_task = tokio::spawn(async move {
                    let mut total = 0usize;
                    for _ in 0..CHUNKS {
                        let f = read_frame(&mut reader, FRAME_LIMITS).await.unwrap();
                        total += f.payload.len();
                    }
                    total
                });
                for f in black_box(&frames) {
                    write_frame(&mut writer, f).await.unwrap();
                }
                drop(writer);
                black_box(read_task.await.unwrap())
            })
        });
    });
    group.bench_function("write_coalesced_frames_1mb", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut writer, mut reader) = tokio::io::duplex(4 * 1024 * 1024);
                let read_task = tokio::spawn(async move {
                    let mut total = 0usize;
                    for _ in 0..CHUNKS {
                        let f = read_frame(&mut reader, FRAME_LIMITS).await.unwrap();
                        total += f.payload.len();
                    }
                    total
                });
                write_frames(&mut writer, black_box(refs.iter().copied()))
                    .await
                    .unwrap();
                drop(writer);
                black_box(read_task.await.unwrap())
            })
        });
    });
    group.finish();
}

criterion_group!(benches, bench_duplex_pipeline, bench_write_coalescing);
criterion_main!(benches);
