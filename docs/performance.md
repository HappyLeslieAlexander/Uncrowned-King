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
| Connection pooling on the client | ✅ | Bounded pool of up to `max_carrier_sessions` (default 4) authenticated carriers (`ClientSessionManager.pool`). New flows go to the least-loaded carrier; a new carrier is opened when the others are at `max_streams` and the pool is not full. |
| Separate latency-sensitive vs bulk carriers | ✅ | Implemented as the bounded least-loaded pool above. SOCKS5 carries no latency-class signal, so least-loaded placement is the principled approximation: a bulk flow that sheds/backpressures on one carrier shares it with at most `max_streams − 1` others rather than every flow, and lone flows tend to land on their own carrier. |
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

**Bulk/latency separation — implemented (client connection pool, §13).** The
client now keeps a bounded pool of up to `max_carrier_sessions` (default 4)
carriers and places each new flow on the least-loaded one, opening another
carrier when the rest are at their stream limit. A bulk flow's shedding or
backpressure is therefore confined to its own carrier instead of every flow, and
a lone bulk flow tends to sit on its own carrier. See
`ClientSessionManager::session_for_new_flow` in `crates/uk-client/src/relay.rs`.

**Remaining future work:**

1. **True per-flow backpressure** (pause reading one flow off a shared carrier
   without head-of-line-blocking others) if even the byte-limited ceiling plus
   pool isolation proves too low for some workloads on a single carrier.
2. **Latency-class hinting** — the pool spreads by load only; SOCKS5 exposes no
   latency class. A future protocol/UX signal could pin known-bulk flows to a
   dedicated carrier explicitly rather than statistically.

## §13 buffer bump revisited

Given the finding above, raising `RELAY_BUFFER_SIZE` to 32 KiB in isolation is
*not* a safe throughput win — it enlarges bursts and lowers the effective
single-flow shed threshold. Any buffer/queue tuning must be evaluated together
with `FLOW_FRAME_QUEUE_CAPACITY` and the pool, using this harness.

## Soak / chaos stability

`soak_sustained_relay_and_chaos` (also `#[ignore]`d) keeps
`SOAK_CONCURRENCY = 16` persistent flows continuously ping-ponging through one
long-lived client session while injecting denied-target flows at 20/s, then
confirms every byte is intact and the session is still healthy. It uses
persistent flows rather than connect churn, so it does not exhaust ephemeral
ports over long runs. Duration via `UK_SOAK_SECONDS` (default 2):

```sh
UK_SOAK_SECONDS=86400 cargo test -p uk-client --test tcp_relay_e2e --release -- \
    --ignored --nocapture soak_sustained_relay_and_chaos
```

Observed (Apple-silicon dev machine, `/usr/bin/time -l`):

| Duration | Round trips | Denied-flow chaos | Max RSS |
| ---: | ---: | ---: | ---: |
| 2 s | ~80 k | 39 | 70.6 MiB |
| 12 s | ~411 k | 235 | 70.5 MiB |

5× the work at the **same RSS** — no memory growth, no leak, no error
accumulation, and the session survived the interleaved denied flows. For a
production soak, run for hours and watch max RSS / file descriptors under
`/usr/bin/time -l` (macOS) or `-v` (Linux).

## Outstanding performance work

1. **Quantify the pool's isolation** — the bounded least-loaded connection pool
   (§13) is now implemented; re-run this harness with a mixed bulk +
   latency-sensitive workload to measure the tail-latency improvement the pool
   gives versus a single carrier, and to confirm the frame-queue / buffer tuning
   holds across multiple carriers.
2. **Vectored/coalesced writes** across frames (measure with the harness first).

The previously-outstanding client connection pool item is done; see the §13
conformance table above.
