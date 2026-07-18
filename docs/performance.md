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
| Reusable buffers (32–64 KiB) | ◑ | `RELAY_BUFFER_SIZE = 16 KiB` today (a reusable boxed buffer per reader task); UDP uses a 64 KiB datagram buffer. Raising it to 32 KiB is **not** a standalone win — see "§13 buffer bump revisited" below: larger reads enlarge bursts and lower the single-flow shed threshold, so it must be tuned together with the per-flow queue and the pool. |
| Per-direction rate counters | ✅ | `record_relay_bytes` tracks bytes by protocol (TCP/UDP) and direction (client↔target), exported as Prometheus counters. |
| Batched writes where possible | ◑ | Each relay frame is one `write_frame`; the payload is copied once and written behind the carrier's buffered writer. Vectored/coalesced writes across frames are a future optimization (measure with the e2e harness first). |
| Connection pooling on the client | ⏳ | Deferred to complete this phase — see below. The client currently multiplexes all flows over one carrier; QUIC already avoids head-of-line blocking at the stream level. |
| Separate latency-sensitive vs bulk carriers | ⏳ | Tied to connection pooling. SOCKS5 carries no latency-class signal, so a bounded least-loaded pool is the planned approximation. |
| QUIC DATAGRAM for UDP | ✅ | UDP data plane uses QUIC DATAGRAM on QUIC sessions, with automatic fallback to `UDP_DATA` frames for oversized payloads. |
| Adaptive fallback when a carrier fails | ✅ | Per-endpoint `quic://`/`tls://` selection with ordered retry gives QUIC-preferred connection and automatic TLS fallback. |

## End-to-end throughput

Full-stack loopback download (target → `uk-server` → `uk-client` → SOCKS
reader), measured by the `#[ignore]`d benchmark `measures_quic_carrier_throughput`.
The client only reads, so the per-flow relay loop is not contended by a
simultaneous upload. It is not a CI gate (see below); run it manually:

```sh
cargo test -p uk-client --test tcp_relay_e2e --release -- \
    --ignored --nocapture measures_quic_carrier_throughput
```

On an unloaded Apple-silicon dev machine, a single QUIC flow sustains
**~130 MiB/s** over a 32 MiB download (machine-relative).

### Finding: high-throughput single-flow shed (drives §13 pooling)

A single high-throughput flow is *shed* once the consuming task falls behind:
the per-flow inbound queue is bounded to `FLOW_FRAME_QUEUE_CAPACITY = 32`
frames of `RELAY_BUFFER_SIZE` (16 KiB) each (≈ 512 KiB), and the **shared**
carrier reader drops a flow whose queue overflows rather than
head-of-line-blocking every other flow on that carrier.

- **This affects both carriers under consumer starvation.** QUIC transport flow
  control paces the *transport*, so on an unloaded machine a QUIC flow sustains;
  but under enough CPU contention (e.g., a loaded CI runner executing the whole
  e2e suite in parallel) the *application* consumer is starved and the queue
  overflows on QUIC too. TLS/TCP has no app-facing pacing and sheds even more
  readily.
- Because completion depends on the consumer keeping pace, an
  "received == total" assertion is **not deterministic under load**, which is
  why the benchmark is `#[ignore]`d rather than a CI gate.
- Same root cause as the earlier "early eof" when raising `RELAY_BUFFER_SIZE`
  to 32 KiB (larger reads → larger bursts → overflow sooner). It is **not** a
  half-close bug; carrier byte ordering is correct.

**Mitigation applied — the byte limit now governs, not a fixed frame count.**
Both per-flow queues (the client's inbound frame queue and the server's
client-to-target write queue) were a fixed 32 frames, so for 16 KiB frames a
flow was shed at ≈ 512 KiB regardless of the configured byte budget. They are
now sized from `max_buffered_bytes_per_flow` (`flow_frame_queue_capacity` /
`target_write_queue_capacity`), so the configured per-flow byte limit is the
real shed threshold — the default 2 MiB (up to 16 MiB) instead of 512 KiB.
Memory stays bounded by the existing byte accounting, which reserves and
releases against the limit; a deeper queue only raises the threshold for a
momentarily-slow consumer. This makes single-flow bulk far more robust on both
carriers; a flow is shed only after it has genuinely buffered its full byte
budget.

**Remaining future work:**

1. **Bulk/latency separation via the client connection pool (§13)** — put a
   bulk flow on its own carrier so its shedding/backpressure never affects
   latency-sensitive flows on other carriers. Still the principled isolation
   fix; the byte-limit sizing above raises the single-flow ceiling but one
   shared carrier still shares a byte budget.
2. **True per-flow backpressure** (pause reading one flow off the shared
   carrier without head-of-line-blocking others) if even the byte-limited
   ceiling proves too low for some workloads.

## §13 buffer bump revisited

Given the finding above, raising `RELAY_BUFFER_SIZE` to 32 KiB in isolation is
*not* a safe throughput win — it enlarges bursts and lowers the effective
single-flow shed threshold. Any buffer/queue tuning must be evaluated together
with `FLOW_FRAME_QUEUE_CAPACITY` and the pool, using this harness.

## Outstanding performance work

1. **Long-running soak (≥24 h) + chaos**: repeated carrier drops, limit
   boundaries, and file-descriptor / memory monitoring, to confirm no leaks or
   unbounded growth.
2. **Client connection pool** (§13): implement the bounded least-loaded pool
   with bulk/latency separation, then re-run this harness to quantify the
   single-flow TLS/TCP throughput it unlocks and validate the frame-queue /
   buffer tuning.

These are the remaining Phase 3 items in `docs/production-roadmap.md`.
