# Changelog

All notable changes to Uncrowned King are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Linux release binaries are now fully-static **musl** builds
  (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) instead of glibc,
  so they run on any Linux without a matching system libc. Both macOS targets
  build on `macos-14` (Apple Silicon), which also cross-compiles the x86_64
  target and avoids the retiring `macos-13` Intel runner.

## [0.1.0] - 2026-07-18

First runnable release of the Uncrowned King v0.1 proxy: an authenticated,
policy-enforced SOCKS5 → UK → target relay over TLS/TCP and QUIC.

### Added

- **Protocol core** (`uk-proto`): binary frames with QUIC-style varints, strict
  target encoding, TCP/UDP relay payloads, and a SETTINGS negotiation.
- **Authentication** (`uk-auth`): challenge-response HMAC bound to the TLS/QUIC
  keying-material exporter, with a replay cache, timestamp-skew bounds, and
  constant-time verification.
- **Policy** (`uk-policy`): deny-all by default, ordered allow/deny rules,
  private/reserved-range denial (including resolved domains), and hard denial of
  cloud metadata endpoints, evaluated after DNS resolution and before dialing.
- **TLS/TCP carrier** (`uk-server`, `uk-client`): TLS 1.3 only, ALPN `uk/1`, no
  0-RTT application data.
- **QUIC carrier**: server and client QUIC carriers sharing the TLS identity and
  ALPN, with the control channel on a server-opened bidirectional stream.
- **Native UDP over QUIC DATAGRAM** on QUIC sessions, with automatic fallback to
  the reliable `UDP_DATA` frame path for oversized payloads.
- **Client carrier selection and fallback**: per-endpoint `tls://` / `quic://`
  scheme with ordered retry (QUIC-preferred, automatic TLS fallback).
- **Client connection pool** (whitepaper §13): a bounded pool of up to
  `max_carrier_sessions` (default 4) authenticated carriers, placing each new
  flow on the least-loaded one and opening another carrier when the others reach
  their stream limit, so a bulk flow's shedding/backpressure stays confined to
  one carrier instead of stalling latency-sensitive flows on the others.
- **SOCKS5 front end**: CONNECT and UDP ASSOCIATE, loopback-guarded by default.
- **Multiplexed TCP and UDP relay** over both carriers, with bounded UDP flow
  recovery after a carrier disconnect.
- **Resource limits**: bounded sessions, handshakes, streams, UDP flows,
  outbound dials, buffered bytes (per session and per flow, sizing the per-flow
  queues), plus idle/handshake/connect/half-close timeouts.
- **Operations**: graceful Ctrl+C/SIGTERM shutdown; atomic SIGHUP reload of
  credentials, policy, and the TLS **and QUIC** certificate/key (new connections
  use the rotated identity, existing connections keep theirs); health,
  readiness, and Prometheus metrics endpoints; structured JSON logging with
  secret redaction and escaped fields.

### Security

- `unsafe_code = "forbid"` workspace-wide; secrets zeroized on drop; sensitive
  file-permission checks on Unix.
- CI: multi-toolchain build/test/clippy, RustSec advisory audit, `cargo-deny`
  (licenses/sources/bans), and libFuzzer smoke over the strict parsers.
- Threat model, key-management SOP, and vulnerability-disclosure policy in
  `docs/` and `SECURITY.md`.

### Performance

- Codec micro-benchmarks (per-packet cost < 100 ns); an e2e download throughput
  harness (QUIC ~130 MiB/s single flow); per-flow queue depth derived from the
  byte limit to avoid premature single-flow shedding; a connection-pool
  latency-isolation benchmark (pool cuts interactive p99 ~2.6× under a
  saturating bulk flow); and a soak/chaos harness showing flat memory across
  sustained load. See `docs/performance.md`.

[Unreleased]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/HappyLeslieAlexander/Uncrowned-King/releases/tag/v0.1.0
