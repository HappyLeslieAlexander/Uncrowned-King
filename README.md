# UncrownedKing

UncrownedKing, abbreviated as UK, is a practical secure proxy protocol built on
standard encrypted transports. The Rust implementation in this repository is
being developed in small, testable increments.

## Current Milestone

The repository currently focuses on the first runnable v0.1 TCP path:

- binary frame and QUIC-style varint encoding in `uk-proto`
- strict target encoding in `uk-proto`
- TCP open/close payload encoding in `uk-proto`
- challenge-response HMAC authentication in `uk-auth`
- minimal policy decisions in `uk-policy`
- TLS/TCP authenticated server sessions in `uk-server`
- SOCKS5 CONNECT entry point and multiplexed TCP relay in `uk-client`

The first runnable proxy target is:

```text
SOCKS5 client -> UK over TLS/TCP -> UK server -> TCP target
```

Server policy is deny-all unless `policy_path` is set in the server config. A
minimal allow policy looks like:

```toml
[[rules]]
action = "allow"
domain_suffix = ".example.com"
port_start = 443
port_end = 443
```

Server limits can advertise and enforce the maximum frame size and concurrent
TCP streams per authenticated session, plus the authenticated session idle
timeout:

```toml
[limits]
max_frame_size = 65536
max_streams = 64
idle_timeout_seconds = 300
```

Set `idle_timeout_seconds = 0` to disable the relay session idle timeout.

## Repository Layout

```text
docs/
  whitepaper.md      Original protocol whitepaper
  spec-v0.1.md       Implementable v0.1 wire specification
  test-vectors.md    Fixed examples for protocol tests
crates/
  uk-proto/          Frame, varint, target, settings, and errors
  uk-auth/           Challenge-response authentication
  uk-policy/         Server-side policy decisions
  uk-server/         Server binary entry point
  uk-client/         Client binary entry point
```

## Development

```sh
cargo check --workspace
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets
```
