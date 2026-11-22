//! Micro-benchmarks for the transport masking hot paths.
//!
//! `prelude_verify` (per-credential HMAC verify) is the server's per-connection
//! admission cost and the numbers to compare against a rustls certificate
//! signature; `stream` measures the steady-state relay cost of the ChaCha20
//! wrapper against raw tokio duplex throughput. Run with `cargo bench -p uk-mask`.

// criterion_group! expands to an undocumented public function.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use uk_mask::{ClientSequence, MaskKeys, MaskedStream, PreludePolicy, ReplayRegistry};

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn bench_prelude(c: &mut Criterion) {
    let mut group = c.benchmark_group("mask_prelude");
    for credential_count in [1_usize, 8, 64] {
        let keys: Vec<MaskKeys> = (0..credential_count)
            .map(|index| MaskKeys::derive(format!("key-{index}").as_bytes(), SECRET))
            .collect();
        let target = &keys[0];
        let prelude = target
            .encode_prelude(PreludePolicy::Fade, &mut StdRng::seed_from_u64(1), 42, 7)
            .unwrap();
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("verify_all_{credential_count}_credentials"), |b| {
            b.iter(|| {
                let matched = uk_mask::verify_prelude(
                    black_box(&keys),
                    black_box(&prelude.bytes),
                    black_box(&prelude.nonce),
                );
                black_box(matched);
            });
        });
        group.bench_function(format!("encode_{credential_count}_set"), |b| {
            let sequence = ClientSequence::new(&mut StdRng::seed_from_u64(2));
            b.iter(|| {
                let counter = sequence.allocate().unwrap();
                let encoded = target.encode_prelude(
                    black_box(PreludePolicy::Fade),
                    &mut StdRng::seed_from_u64(3),
                    sequence.identity(),
                    black_box(counter),
                );
                black_box(encoded.ok());
            });
        });
    }
    group.finish();
}

fn bench_replay(c: &mut Criterion) {
    let mut group = c.benchmark_group("mask_replay");
    let mut registry = ReplayRegistry::new(16_384);
    let mut next = 1_u64;
    group.throughput(Throughput::Elements(1));
    group.bench_function("commit_new_identity", |b| {
        b.iter(|| {
            let counter = next;
            next += 1;
            black_box(registry.commit(black_box(counter), black_box(counter)));
        });
    });
    group.finish();
}

fn bench_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("mask_stream");
    let keys = MaskKeys::derive(b"bench", SECRET);
    let nonce = [9; 12];
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for size in [16 * 1024_usize, 256 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("masked_duplex_{size}"), |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let keys = &keys;
                    let nonce = &nonce;
                    let (client_side, server_side) = duplex(256 * 1024);
                    let mut client = MaskedStream::new_client(client_side, keys, nonce);
                    let mut server = MaskedStream::new_server(server_side, keys, nonce);
                    let payload = vec![0xa5_u8; size];
                    let writer = tokio::spawn(async move {
                        client.write_all(&payload).await.unwrap();
                        client.flush().await.unwrap();
                    });
                    let mut received = vec![0_u8; size];
                    server.read_exact(&mut received).await.unwrap();
                    writer.await.unwrap();
                    received
                })
            });
        });
        group.bench_function(format!("plain_duplex_{size}"), |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let (mut client, mut server) = duplex(256 * 1024);
                    let payload = vec![0xa5_u8; size];
                    let writer = tokio::spawn(async move {
                        client.write_all(&payload).await.unwrap();
                        client.flush().await.unwrap();
                    });
                    let mut received = vec![0_u8; size];
                    server.read_exact(&mut received).await.unwrap();
                    writer.await.unwrap();
                    received
                });
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_prelude, bench_replay, bench_stream);
criterion_main!(benches);
