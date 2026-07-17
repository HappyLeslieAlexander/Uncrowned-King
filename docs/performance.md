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

Full-stack loopback download (target → `uk-server` → `uk-client` → SOCKS reader)
measured by `measures_quic_carrier_throughput` in the e2e suite (a client that
only reads, so the per-flow relay loop is not contended by a simultaneous
upload). Machine-relative:

| Carrier | Single-flow download | Notes |
| --- | ---: | --- |
| QUIC | ~130 MiB/s (32 MiB transfer) | Sustained; stable across runs. |
| TLS/TCP | not sustained on a single flow | Shed — see below. |

### Finding: single-flow shed on TLS/TCP (drives §13 pooling)

A single high-throughput flow over the **TLS/TCP** carrier is *shed* once the
consumer falls behind: the per-flow inbound queue is bounded to
`FLOW_FRAME_QUEUE_CAPACITY = 32` frames of `RELAY_BUFFER_SIZE` (16 KiB) each
(≈ 512 KiB), and the **shared** carrier reader drops a flow whose queue
overflows rather than head-of-line-blocking every other flow on that carrier.
When the source outruns the consumer (easy over loopback TLS, which has no
transport pacing back to the app), the queue overflows and the flow is closed.

- **QUIC does not hit this**: QUIC stream flow control paces the source to the
  consumer, so the per-flow queue stays bounded and the flow sustains.
- This is the same root cause as the earlier "early eof" seen when raising
  `RELAY_BUFFER_SIZE` to 32 KiB — larger server reads produced larger bursts
  that overflowed the client's frame queue sooner. It is **not** a half-close
  bug; ordering across the carrier is correct.

**Mitigations (future work, in priority order):**

1. **Bulk/latency separation via the client connection pool (§13)** — put a
   bulk flow on its own carrier so shedding/backpressure never affects
   latency-sensitive flows. This is the principled fix and the main reason the
   pool is worthwhile.
2. **Raise `FLOW_FRAME_QUEUE_CAPACITY`** (e.g., 32 → 256+) to lift the
   single-flow shed threshold at modest memory cost, as an interim tuning knob.
3. **Bounded per-flow backpressure** to the carrier reader that does not
   head-of-line-block other flows (more invasive).

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
