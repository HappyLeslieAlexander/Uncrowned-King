//! Micro-benchmarks for the per-packet codec hot paths.
//!
//! These measure the CPU cost of the encode/decode routines that run once per
//! relayed frame or datagram, so they bound the protocol's per-packet
//! overhead independent of transport and syscall costs. Run with `cargo bench
//! -p uk-proto`.

// criterion_group! expands to an undocumented public function.
#![allow(missing_docs)]

use std::hint::black_box;

use bytes::{Bytes, BytesMut};
use criterion::{Criterion, criterion_group, criterion_main};
use uk_proto::{
    Frame, FrameLimits, FrameType, Settings, Target, datagram,
    settings::{PROTOCOL_REVISION_V0_1, SettingKey},
    varint,
};

const FRAME_LIMITS: FrameLimits = FrameLimits {
    max_frame_size: 65_536,
};

fn bench_varint(c: &mut Criterion) {
    let mut group = c.benchmark_group("varint");
    for value in [37_u64, 15_293, 494_878_333, 4_611_686_018_427_387_000] {
        group.bench_function(format!("roundtrip/{value}"), |b| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(8);
                varint::encode(black_box(value), &mut buf).unwrap();
                let mut cursor = buf.as_slice();
                black_box(varint::decode(&mut cursor).unwrap())
            });
        });
    }
    group.finish();
}

fn bench_frame(c: &mut Criterion) {
    // A realistic ~1400-byte TCP_DATA relay frame.
    let payload = Bytes::from(vec![0x5a_u8; 1400]);
    let frame = Frame::new(FrameType::TcpData, 0, 1, payload).unwrap();
    let encoded = frame.encode().unwrap();

    let mut group = c.benchmark_group("frame");
    group.bench_function("encode/tcp_data_1400", |b| {
        b.iter(|| black_box(black_box(&frame).encode().unwrap()));
    });
    group.bench_function("decode/tcp_data_1400", |b| {
        b.iter(|| {
            let mut cursor = encoded.clone();
            black_box(Frame::decode(&mut cursor, FRAME_LIMITS).unwrap())
        });
    });
    group.finish();
}

fn bench_target(c: &mut Criterion) {
    let mut ipv4 = BytesMut::new();
    Target::Ipv4([93, 184, 216, 34].into(), 443)
        .encode(&mut ipv4)
        .unwrap();
    let ipv4 = ipv4.freeze();

    let mut domain = BytesMut::new();
    Target::Domain("www.example.com".to_owned(), 443)
        .encode(&mut domain)
        .unwrap();
    let domain = domain.freeze();

    let mut group = c.benchmark_group("target");
    group.bench_function("decode/ipv4", |b| {
        b.iter(|| {
            let mut cursor = ipv4.clone();
            black_box(Target::decode(&mut cursor).unwrap())
        });
    });
    group.bench_function("decode/domain", |b| {
        b.iter(|| {
            let mut cursor = domain.clone();
            black_box(Target::decode(&mut cursor).unwrap())
        });
    });
    group.finish();
}

fn bench_datagram(c: &mut Criterion) {
    let payload = vec![0x5a_u8; 1200];
    let mut encoded = BytesMut::new();
    datagram::encode(1, &payload, &mut encoded).unwrap();
    let encoded = encoded.freeze();

    let mut group = c.benchmark_group("datagram");
    group.bench_function("encode/udp_1200", |b| {
        b.iter(|| {
            let mut out = BytesMut::with_capacity(payload.len() + 8);
            datagram::encode(black_box(1), black_box(&payload), &mut out).unwrap();
            black_box(out)
        });
    });
    group.bench_function("decode/udp_1200", |b| {
        b.iter(|| black_box(datagram::decode(black_box(encoded.clone())).unwrap()));
    });
    group.finish();
}

fn bench_settings(c: &mut Criterion) {
    let mut settings = Settings::default();
    settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V0_1);
    settings.set(SettingKey::MaxFrameSize, 65_536);
    settings.set(SettingKey::MaxStreams, 64);
    settings.set(SettingKey::MaxUdpFlows, 64);
    settings.set(SettingKey::SupportsUdpDatagram, 1);
    settings.set(SettingKey::SupportsUdpStreamFallback, 1);
    let mut encoded = BytesMut::new();
    settings.encode(&mut encoded).unwrap();
    let encoded = encoded.freeze();

    let mut group = c.benchmark_group("settings");
    group.bench_function("decode+negotiate", |b| {
        b.iter(|| {
            let mut cursor = encoded.clone();
            let decoded = Settings::decode(&mut cursor).unwrap();
            black_box(decoded.negotiated_v0_1().unwrap())
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_varint,
    bench_frame,
    bench_target,
    bench_datagram,
    bench_settings
);
criterion_main!(benches);
