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
- QUIC authenticated server sessions in `uk-server`, sharing the TLS 1.3
  identity and `uk/1` ALPN, with the control channel on a server-opened
  bidirectional stream
- client QUIC carrier with per-endpoint carrier selection and automatic
  fallback (prefer `quic://`, fall back to `tls://`)
- SOCKS5 CONNECT and UDP ASSOCIATE entry points in `uk-client`
- multiplexed TCP relay and UDP relay over the TLS/TCP and QUIC carriers
- native UDP over QUIC DATAGRAM on QUIC sessions, with automatic fallback to
  the reliable `UDP_DATA` frame path for oversized payloads
- bounded UDP flow recovery after a carrier disconnect without closing the SOCKS association
- graceful Ctrl+C/SIGTERM shutdown for long-running client and server listeners
- capped exponential retry for transient client and server listener accept errors
- bounded client and server health, readiness, and Prometheus metrics endpoints
- atomic SIGHUP reload for server and client TLS/auth configuration, rotating
  both the TLS/TCP and QUIC server identities for new connections
- nonce-matched PING/PONG keepalive for active relay flows
- negotiated UDP flow limits and idle UDP flow cleanup on both client and server
- SETTINGS-advertised UDP stream fallback capability for the TLS/TCP carrier

The first runnable proxy targets are:

```text
SOCKS5 client -> UK over TLS/TCP -> UK server -> TCP target
SOCKS5 client -> UK over TLS/TCP -> UK server -> UDP target
SOCKS5 client -> UK over QUIC    -> UK server -> TCP target
SOCKS5 client -> UK over QUIC    -> UK server -> UDP target
```

## Carriers

The server always listens for the TLS/TCP carrier on `listen`. Set
`quic_listen` to a UDP `host:port` to additionally accept the QUIC carrier;
both carriers share the configured certificate, key, and `uk/1` ALPN, and
reject 0-RTT application data. On QUIC sessions the UDP data plane uses native
QUIC DATAGRAM (the server advertises `supports_udp_datagram = 1`): UDP payloads
travel as unreliable datagrams, and any payload too large for the current
datagram size falls back to the reliable `UDP_DATA` frame path. UDP relay
control (`UDP_OPEN`/`UDP_CLOSE`) always uses the reliable stream. On the
TLS/TCP carrier, UDP relay uses the stream path throughout.

```toml
listen = "127.0.0.1:9443"
quic_listen = "127.0.0.1:9443"
```

The client selects a carrier per server endpoint from an optional URI scheme on
`server_addr` and each `server_addrs` entry. A bare `host:port` (or a
`tls://host:port`) uses the TLS/TCP carrier; `quic://host:port` uses QUIC.
Because endpoints are tried in order, listing a `quic://` endpoint ahead of a
`tls://` one gives QUIC-preferred connection with automatic TLS fallback:

```toml
server_addr = "quic://server.example.com:9443"
server_addrs = ["tls://server.example.com:9443"]
```

Changing `quic_listen` requires a server restart, like `listen`. SIGHUP
identity rotation applies to both carriers: a reload atomically rotates the
TLS/TCP acceptor and the QUIC endpoint's certificate for new connections, while
existing connections keep the identity they were accepted with.

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
carrier sessions, concurrent unauthenticated handshakes, concurrent TCP streams
per authenticated session, in-flight target socket dials per session, concurrent
UDP relay flows, queued client-to-target bytes per session and per flow, plus
idle timeouts:

```toml
auth_skew_seconds = 30

[limits]
max_pre_auth_bytes = 4096
max_frame_size = 65536
max_sessions = 1024
max_handshakes = 1024
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
shutdown_timeout_seconds = 30
replay_cache_window_seconds = 300
replay_cache_max_entries = 65536
```

Set `idle_timeout_seconds = 0` to disable the relay session idle timeout.
Set `handshake_timeout_seconds = 0` to disable the TLS/auth handshake timeout.
Set `target_connect_timeout_seconds = 0` to disable the server target dial timeout.
Set `tcp_half_close_timeout_seconds = 0` to disable the TCP half-close drain timeout.
Set `udp_flow_idle_timeout_seconds = 0` to disable server-side UDP flow idle cleanup.
Set `shutdown_timeout_seconds = 0` to wait indefinitely for listener and relay
session tasks to finish after shutdown; otherwise remaining tasks are aborted
after the timeout.
Set `max_udp_flows = 0` to disable UDP relay.
`auth_skew_seconds` defaults to 30 and bounds accepted client and server
authentication timestamps.
Replay cache limits must be greater than zero. `max_pre_auth_bytes` must be at
least 75 bytes so a minimum `AUTH_RESPONSE` can fit. `max_pre_auth_bytes`,
`max_frame_size`, `max_buffered_bytes_per_session`, and
`max_buffered_bytes_per_flow` must be at most 16777216 bytes.
At least one credential is required. Credential `key_id` values must be unique.
When set, `policy_group` must be non-empty printable text.

Set `observability_listen = "127.0.0.1:9090"` at the top level of the server
config to enable the operational HTTP listener. It is disabled when omitted and
serves only `GET /healthz`, `GET /readyz`, and `GET /metrics`. Readiness drops
before relay shutdown begins. Metrics expose accepted connections, active and
failed handshakes, authenticated and rejected sessions, TCP/UDP open requests
and bounded failure reasons, active flows, and successfully relayed payload
bytes by protocol and direction in Prometheus text format. Security config
generation and reload attempt, success, and failure counters make reload
outcomes observable. The endpoint has no authentication; bind it to loopback or
a firewall-protected management network. Requests are limited to an 8 KiB
header, a five-second read timeout, and 32 concurrent connections.

The client supports the same operational endpoints with
`observability_listen = "127.0.0.1:9091"`. Its Prometheus metrics report the
active config generation and reload outcomes, accepted and rejected SOCKS5
connections, carrier connection attempts and failures, active and draining
sessions, TCP/UDP flow opens, and successfully relayed payload bytes in both
directions. Endpoint attempts use fixed `success`/`failure` outcomes, while
failures are classified with bounded `tcp`, `tls`, `auth`, `settings`,
`timeout`, `protocol`, and `other` phase labels without exposing endpoint
addresses. Client readiness drops before SOCKS shutdown and the management
listener remains available while active connections drain. This endpoint is
also unauthenticated and should be bound only to loopback or a protected
management network; it uses the same request size, timeout, and concurrency
limits as the server endpoint.

Client configs may also set `handshake_timeout_seconds = 10` to bound each
server endpoint attempt, including TCP connect, TLS handshake, authentication
exchange, and SETTINGS read. Set `server_addrs = ["backup.example.com:443"]`
to try fallback server endpoints after `server_addr`; each endpoint receives
its own handshake timeout budget. After all endpoints fail,
`server_connect_retry_delay_millis = 250` briefly reuses the recent failure for
other waiting SOCKS requests instead of immediately dialing the same failed
endpoints again. Set it to `0` to disable this cooldown. Fallback endpoints must
not duplicate `server_addr` or each other.
When running the SOCKS5 listener, `socks_handshake_timeout_seconds = 10` bounds
the local SOCKS greeting and CONNECT request. `tcp_open_timeout_seconds = 10`
bounds waiting for a UK TCP open response from the server.
`udp_flow_idle_timeout_seconds = 120` bounds how long a per-target UDP flow may
sit idle in a local SOCKS UDP association before the client closes it. UDP flow
activity is bidirectional: downstream target replies also refresh the idle
timer. A failed carrier send removes only the matching stale UDP flow and makes
one bounded attempt to reconnect the UK session and resend the datagram; the
SOCKS UDP association remains open when recovery succeeds. SOCKS5 UDP ASSOCIATE
honors the client-declared UDP source endpoint:
declared non-zero addresses or ports must match incoming UDP datagrams, while
an all-zero endpoint learns the first accepted peer.
`shutdown_timeout_seconds = 30` bounds how long the local SOCKS listener waits
for active connection tasks after Ctrl+C/SIGTERM before aborting the stragglers;
set it to `0` to wait indefinitely.
`max_pending_open_bytes = 65536` bounds local bytes buffered before that open
response arrives.
`max_socks_connections = 1024` bounds concurrent local SOCKS connections before
and during relay. `max_buffered_bytes_per_session = 16777216` and
`max_buffered_bytes_per_flow = 2097152` bound queued server-to-local relay bytes
per UK session and per flow.

Example configs live under `examples/`; see `examples/README.md` for local
certificate generation. Relative file paths inside config files are resolved
from the config file's directory. Client and server TOML files contain shared
secrets, and the server private key is sensitive; on Unix-like systems they
must not be accessible by group or other users. For local examples:

```sh
chmod 600 examples/server-key.pem examples/server.toml examples/client.toml
```

Validate configs without opening listeners or outbound sessions:

```sh
uk-server --config examples/server.toml config-check
uk-client --config examples/client.toml config-check
```

Start the local TLS/TCP server and SOCKS5 client in separate terminals:

```sh
uk-server --config examples/server.toml serve
uk-client --config examples/client.toml socks5 --listen 127.0.0.1:1080
```

The `uk-client` binary refuses to expose its unauthenticated SOCKS5 listener on
a non-loopback address by default. Controlled LAN deployments must explicitly
acknowledge that exposure with `--allow-non-loopback` and provide host firewall
or network access controls.

Both long-running listeners stop gracefully on Ctrl+C or SIGTERM. On Unix,
`uk-server` reloads its TLS certificate and private key, credentials, credential
status and validity windows, policy, and `auth_skew_seconds` from its original
config path on `SIGHUP`. A reload is published atomically only after the new TLS
identity, credentials, and policy validate. Existing TCP and UDP flows continue;
new handshakes use the new TLS identity and credentials, while new flow opens on
existing sessions use the new policy and require the authenticated key to remain
active in the same policy group. Removing, disabling, expiring, or reassigning a
key therefore blocks new flows on its existing sessions without terminating
flows that are already open. Listener addresses, resource limits, and timeout
settings still require a process restart.

On Unix, `uk-client` also reloads its server endpoints, TLS server name and CA,
key id and shared secret, handshake and retry timing, TCP open and UDP flow idle
timeouts, and per-session/per-flow buffer limits on `SIGHUP`. Candidate CA and
authentication material are validated before the new client config generation
is published. Existing SOCKS flows continue on their old carrier, while new TCP
and UDP flows immediately use a carrier from the new generation. A draining old
carrier closes automatically after its final flow ends. If a reload races an
in-flight handshake, that handshake cannot publish a stale session or cache a
stale connection failure after the reload. `socks_handshake_timeout_seconds`,
`shutdown_timeout_seconds`, `max_socks_connections`, and
`observability_listen` still require a client restart because the listeners own
those resources.

Both binaries accept global `--log-format text|json` output selection and use
`RUST_LOG` for filtering. JSON mode preserves structured event fields for log
collection systems. Server connections, local SOCKS connections, and client UK
sessions carry process-local correlation IDs; these IDs contain no protocol
nonce or authentication secret.

```sh
RUST_LOG=info uk-server --config examples/server.toml --log-format json serve
```

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
cargo build --workspace --release --locked
```

GitHub Actions runs the same checks on Rust 1.85 and stable, builds release
binaries on stable, audits `Cargo.lock` against RustSec advisories and runs
`cargo-deny` (licenses, sources, bans) on dependency changes and a daily
schedule, and fuzzes the strict parsers when they change.

## Security

- Threat model, security invariants, and residual risks:
  [`docs/threat-model.md`](docs/threat-model.md)
- Key and certificate lifecycle (generation, permissions, rotation,
  revocation): [`docs/key-management.md`](docs/key-management.md)
- Vulnerability disclosure policy: [`SECURITY.md`](SECURITY.md)

Report vulnerabilities privately via GitHub's "Report a vulnerability" — not a
public issue. See [`SECURITY.md`](SECURITY.md).
