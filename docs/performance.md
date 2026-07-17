# Uncrowned King Performance

This document records the performance baseline and the review against the
whitepaper §13 performance requirements. Numbers come from the criterion
micro-benchmarks in `crates/uk-proto/benches/codec.rs`; reproduce with:

```sh
cargo bench -p uk-proto
```

## Codec micro-benchmarks

These measure the per-packet CPU cost of the encode/decode hot paths that run
once per relayed frame or datagram, isolated from transport and syscall costs.
Measured on an Apple silicon dev machine, release profile (`lto = "thin"`,
`codegen-units = 1`). Treat absolute values as machine-relative; the point is
the order of magnitude.

| Operation | Time |
| --- | ---: |
| UK varint encode+decode roundtrip | ~14 ns |
| Frame decode (1400 B `TCP_DATA`) | ~6.7 ns |
| Frame encode (1400 B `TCP_DATA`) | ~62 ns |
| Target decode (IPv4) | ~7.5 ns |
| Target decode (domain) | ~29 ns |
| Datagram decode (1200 B UDP) | ~8.3 ns |
| Datagram encode (1200 B UDP) | ~28 ns |
| SETTINGS decode + negotiate | ~67 ns |

**Interpretation.** Per-packet codec cost is well under 100 ns, i.e. tens of
millions of packets/second of pure framing work per core. The relay's
throughput ceiling is therefore set by the transport (TLS/QUIC crypto), socket
syscalls, and copies — not by UK's framing. Frame encode is dominated by the
payload copy into the output buffer; decode is near-free because it parses the
header and slices the payload without copying.

## §13 conformance review

| §13 recommendation | Status | Notes |
| --- | --- | --- |
| Reusable buffers (32–64 KiB) | ◑ | `RELAY_BUFFER_SIZE = 16 KiB` today (a reusable boxed buffer per reader task); UDP uses a 64 KiB datagram buffer. Raising the TCP relay buffer to 32 KiB to meet §13 is pending: a first attempt surfaced a Linux-only "early eof" in the large-payload/immediate-close e2e test, so the bump will be applied and validated with the end-to-end throughput harness (which reproduces on Linux) rather than blind. |
| Per-direction rate counters | ✅ | `record_relay_bytes` tracks bytes by protocol (TCP/UDP) and direction (client↔target), exported as Prometheus counters. |
| Batched writes where possible | ◑ | Each relay frame is one `write_frame`; the payload is copied once and written behind the carrier's buffered writer. Vectored/coalesced writes across frames are a future optimization (measure with the e2e harness first). |
| Connection pooling on the client | ⏳ | Deferred to complete this phase — see below. The client currently multiplexes all flows over one carrier; QUIC already avoids head-of-line blocking at the stream level. |
| Separate latency-sensitive vs bulk carriers | ⏳ | Tied to connection pooling. SOCKS5 carries no latency-class signal, so a bounded least-loaded pool is the planned approximation. |
| QUIC DATAGRAM for UDP | ✅ | UDP data plane uses QUIC DATAGRAM on QUIC sessions, with automatic fallback to `UDP_DATA` frames for oversized payloads. |
| Adaptive fallback when a carrier fails | ✅ | Per-endpoint `quic://`/`tls://` selection with ordered retry gives QUIC-preferred connection and automatic TLS fallback. |

## Outstanding performance work

1. **End-to-end throughput and latency** (client → server → target over
   loopback), for TCP and UDP, on both carriers. Needs a measurement harness
   that spins up the full stack and pushes a fixed volume; record P50/P99
   latency and sustained throughput here.
2. **Long-running soak (≥24 h) + chaos**: repeated carrier drops, limit
   boundaries, and file-descriptor / memory monitoring, to confirm no leaks or
   unbounded growth.
3. **Client connection pool** (§13): implement the bounded least-loaded pool
   and use the throughput harness to quantify its benefit on the TLS/TCP
   carrier before committing to it.

These are the remaining Phase 3 items in `docs/production-roadmap.md`.
