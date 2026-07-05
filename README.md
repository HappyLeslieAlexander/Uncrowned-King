# Uncrowned King

Uncrowned King, abbreviated as UK, is a practical secure proxy protocol built on
standard encrypted transports. The Rust implementation in this repository is
being developed in small, testable increments.

## Current Milestone

The repository currently focuses on the first runnable v0.1 TLS/TCP carrier:

- binary frame and QUIC-style varint encoding in `uk-proto`
- strict target encoding in `uk-proto`
- TCP open/close payload encoding in `uk-proto`
- challenge-response HMAC authentication in `uk-auth`
- minimal policy decisions in `uk-policy`
- TLS/TCP authenticated server sessions in `uk-server`
- SOCKS5 CONNECT and UDP ASSOCIATE entry points in `uk-client`
- multiplexed TCP relay and UDP relay over the TLS/TCP carrier
- graceful Ctrl+C/SIGTERM shutdown for long-running client and server listeners
- nonce-matched PING/PONG keepalive for active relay flows
- negotiated UDP flow limits and idle UDP flow cleanup on both client and server
- SETTINGS-advertised UDP stream fallback capability for the TLS/TCP carrier

The first runnable proxy targets are:

```text
SOCKS5 client -> UK over TLS/TCP -> UK server -> TCP target
SOCKS5 client -> UK over TLS/TCP -> UK server -> UDP target
```

Server policy is deny-all unless `policy_path` is set in the server config. A
minimal public-domain policy should deny private resolved addresses before
allowing external domains:

```toml
[[rules]]
action = "deny"
private = true

[[rules]]
action = "allow"
domain_suffix = ".example.com"
port_start = 443
port_end = 443
```

Rules are evaluated in order; the first matching rule wins.
`private = true` matches private, loopback, link-local, documentation,
multicast, unspecified, shared, benchmarking, and reserved IP ranges, including
resolved domain addresses. Known cloud metadata service IPs are denied before
ordered rules are evaluated, including `169.254.169.254`, `100.100.100.200`,
and `fd00:ec2::254`.

Server limits can advertise and enforce the maximum frame size, concurrent
carrier sessions, concurrent TCP streams per authenticated session, in-flight
target socket dials per session, concurrent UDP relay flows, queued
client-to-target bytes per session and per flow, plus idle timeouts:

```toml
[limits]
max_pre_auth_bytes = 4096
max_frame_size = 65536
max_sessions = 1024
max_streams = 64
max_udp_flows = 64
max_outbound_dials_per_session = 16
max_buffered_bytes_per_session = 16777216
idle_timeout_seconds = 300
max_buffered_bytes_per_flow = 2097152
handshake_timeout_seconds = 10
target_connect_timeout_seconds = 10
tcp_half_close_timeout_seconds = 30
udp_flow_idle_timeout_seconds = 120
replay_cache_window_seconds = 300
replay_cache_max_entries = 65536
```

Set `idle_timeout_seconds = 0` to disable the relay session idle timeout.
Set `handshake_timeout_seconds = 0` to disable the TLS/auth handshake timeout.
Set `target_connect_timeout_seconds = 0` to disable the server target dial timeout.
Set `tcp_half_close_timeout_seconds = 0` to disable the TCP half-close drain timeout.
Set `udp_flow_idle_timeout_seconds = 0` to disable server-side UDP flow idle cleanup.
Set `max_udp_flows = 0` to disable UDP relay.
Replay cache limits must be greater than zero. `max_pre_auth_bytes` must be at
least 75 bytes so a minimum `AUTH_RESPONSE` can fit. `max_pre_auth_bytes`,
`max_frame_size`, `max_buffered_bytes_per_session`, and
`max_buffered_bytes_per_flow` must be at most 16777216 bytes.
At least one credential is required. Credential `key_id` values must be unique.
When set, `policy_group` must be non-empty printable text.

Client configs may also set `handshake_timeout_seconds = 10` to bound the
server connection, TLS handshake, authentication exchange, and SETTINGS read.
Set `server_addrs = ["backup.example.com:443"]` to try fallback server
endpoints after `server_addr` within that same timeout. Fallback endpoints must
not duplicate `server_addr` or each other.
When running the SOCKS5 listener, `socks_handshake_timeout_seconds = 10` bounds
the local SOCKS greeting and CONNECT request. `tcp_open_timeout_seconds = 10`
bounds waiting for a UK TCP open response from the server.
`udp_flow_idle_timeout_seconds = 120` bounds how long a per-target UDP flow may
sit idle in a local SOCKS UDP association before the client closes it. UDP flow
activity is bidirectional: downstream target replies also refresh the idle
timer.
`max_pending_open_bytes = 65536` bounds local bytes buffered before that open
response arrives.
`max_socks_connections = 1024` bounds concurrent local SOCKS connections before
and during relay. `max_buffered_bytes_per_session = 16777216` and
`max_buffered_bytes_per_flow = 2097152` bound queued server-to-local relay bytes
per UK session and per flow.

Example configs live under `examples/`; see `examples/README.md` for local
certificate generation. Validate configs without opening listeners or outbound
sessions:

```sh
uk-server --config examples/server.toml config-check
uk-client --config examples/client.toml config-check
```

Start the local TLS/TCP server and SOCKS5 client in separate terminals:

```sh
uk-server --config examples/server.toml serve
uk-client --config examples/client.toml socks5 --listen 127.0.0.1:1080
```

Both long-running listeners stop gracefully on Ctrl+C or SIGTERM.

Configured endpoints use `host:port` syntax. IPv6 literals must be bracketed,
for example `[::1]:9443`; port `0` is rejected by config validation.

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
cargo fmt --all --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```
