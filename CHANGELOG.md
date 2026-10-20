# Changelog

All notable changes to Uncrowned King are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-10-20

### Security

- **Early fixed-header bounds validation (`uk-proto`)**: `read_frame` now validates fixed-header wire bounds (`is_valid_type`, minimum payload length) before decoding variable-length integers, preventing malformed frame parsing denial-of-service.
- **IPv4-mapped IPv6 address canonicalization (`uk-proto`)**: `validate_observability_bind` canonicalizes IPv4-mapped IPv6 addresses (e.g. `::ffff:0.0.0.0`) to reject wildcard bindings consistently across address families.
- **Pre-allocation bounded validation (`uk-auth`)**: `AuthResponse::decode` strictly validates `key_id_len <= MAX_KEY_ID_LEN` before reserving buffer memory, preventing pre-authentication memory exhaustion from inflated headers.
- **Configurable auth rate limiting (`uk-server`)**: support explicitly disabling auth failure rate limiting with `auth_rate_limit_failures = 0` without thread panics or infinite loops.
- **Endpoint address validation (`uk-server`)**: added strict socket address validation for the QUIC listener on startup and SIGHUP reload, matching TLS listener invariants.
- **Fail-closed Helm secret guardrails (`deploy`)**: Helm templates now validate authentication keys and TLS secrets at render time, failing closed if placeholder or empty values are provided.
- **Tightened default network egress policies (`deploy`)**: Kubernetes and Helm deployment manifests restrict egress to cluster DNS and proxy targets, preventing lateral cluster movement.

### Fixed

- **QUIC idle timeout configuration (`uk-server`)**: `quic::listen` now correctly applies the configured `idle_timeout` into `quinn::TransportConfig` instead of relying on default timeout settings.
- **Relay flow cleanup on peer dial/error (`uk-server`)**: TCP and UDP relay workers immediately tear down active flow registrations (`finish_tcp_flow` / `finish_udp_flow`) when dialer or peer errors occur, preventing dead flow table leaks.
- **Session limit error delivery timeout (`uk-server`)**: error frame writes during session limit rejection are now guarded by a 5-second timeout and listener shutdown cancellation watcher, preventing stalled error tasks during connection surges.
- **Active state limits validation on SIGHUP (`uk-server`)**: configuration reload validates that current active session counts and listener configurations remain compliant before applying changes atomically.
- **QUIC client multi-address fallback & socket cleanup (`uk-client`)**: QUIC client resolves and iterates through all candidate `SocketAddr` entries, immediately releasing unbound/failed sockets to eliminate UDP socket leaks.
- **QUIC transport degradation caching (`uk-client`)**: transport-level handshake failures record an endpoint penalty immediately, triggering fast TLS fallback without redundant timeout stalls.
- **Filter draining sessions in connection pool (`uk-client`)**: `first_live_session` excludes sessions in `Draining` state, ensuring new application streams are only scheduled on fully active carriers.
- **Downward API POD_IP observability binding (`deploy`)**: Kubernetes manifests and Helm templates inject `status.podIP` via Downward API for metrics and health listeners, ensuring non-wildcard binding compliance in dual-stack and IPv6 environments.
- **Flexible client deployment modes (`deploy`)**: added Helm support for running clients as standard `Deployment`s alongside `DaemonSet`s for specialized cluster topologies.
- **Documentation buffer limits (`docs`)**: corrected `docs/tuning.md` buffer recommendations to align with the 16 MiB protocol ceiling.

## [1.0.0] - 2026-10-17

### Added

- **Fuzz coverage for all untrusted-input parsers**: five new libfuzzer targets — `datagram_decode`, `settings_decode`, `error_payload_decode`, `frame_reader` (adversarial chunk splits plus a differential check that incremental decoding matches one-shot `Frame::decode`), and `auth_verify` (HMAC/tag/timestamp/replay paths on arbitrary bytes). All ran clean in smoke testing.
- **QUIC relay tests**: concurrent TCP flow multiplexing over one QUIC carrier, QUIC handshake-failure fallback to TLS, and concurrent UDP associations over one carrier.
- **Real SIGHUP end-to-end test** (`uk-server/tests/sighup_reload_e2e.rs`): spawns the actual server binary, rotates TLS certificates on disk, delivers SIGHUP, and verifies new connections serve the rotated identity while pre-existing connections survive — exercising the true signal path, not a simulation.
- **Soak test runs in CI**: `soak_sustained_relay_and_chaos` is no longer `#[ignore]`d (passes reliably with a ~2s default); set `UK_SOAK_SECONDS` for manual long-duration runs.
- **Criterion benchmarks**: handshake auth operations (`uk-auth/benches/auth.rs`) and the frame pipeline (`uk-proto/benches/pipeline.rs`: duplex round-trip, coalesced vs. single writes).

### Changed

- **Removed `AuthChallenge.session_id` from the wire format** (1.0 protocol-freeze decision, 2026-10-16): the 16-byte field was generated per handshake and covered by the authentication MAC but consumed by nothing — replay protection uses `server_nonce`, whose 32 bytes already supply fresh challenge entropy. This supersedes the earlier "keep `session_id`" note, which was recorded without approval. Test vectors regenerated.
- **`protocol_revision` is now 2**: revision 1 denotes the retired 0.x experimental wire format and is rejected. Negotiation stays exact-match with no fallback (fail closed).
- **Frame type registry frozen for 1.0**: `0x00` is permanently illegal; `0x06–0x0F`, `0x13–0x1F`, `0x23–0x2F`, `0x33–0xEF` are reserved for future standard types; `0xF0–0xFF` is the experimental range (bilateral agreement required, negotiated out of band). Unknown frame types still terminate the session (fail closed) — now a documented 1.0 guarantee.
- **Relay data plane no longer allocates per frame**: `write_frame` encodes the header into a 20-byte stack buffer and emits header+payload via vectored writes. Wire bytes are identical. Measured duplex throughput: 2.80 → 5.84 GiB/s (+108%).
- **Handshake/auth buffers exactly pre-sized** (no more reserve→realloc growth): auth verify 4.0× faster, `Frame::encode` ~16% faster.
- **Import hygiene**: removed all 16 `#![allow(unused_imports, clippy::wildcard_imports)]` attributes from relay modules; 39 glob imports replaced with explicit lists, 100+ unused imports dropped (net -207 lines). Unused imports now fail CI instead of being silently suppressed.

### Security

- **Unauthenticated observability endpoint hardening**: wildcard binds (`0.0.0.0`, `[::]`) for `observability_listen` are now rejected at startup in both `uk-server` and `uk-client` — the `/healthz`, `/readyz` and `/metrics` endpoints have no authentication, so a wildcard bind on a host with a public address would expose them to the internet. Specific non-loopback binds (e.g. a Kubernetes pod IP) are still allowed but log a loud warning. New shared validator `uk_proto::validate_observability_bind`.
- **Peer-advertised SETTINGS bounds**: `negotiated_v0_1` now rejects `max_streams`/`max_udp_flows` above 1,000,000 and `idle_timeout_seconds` above 30 days instead of trusting unbounded peer values when sizing admission semaphores and timers.

### Fixed

- **quinn-proto 0.11.16 → 0.11.19**: fixes RUSTSEC-2026-0338 through RUSTSEC-2026-0342 (remote peer could panic quinn-proto with zero-length STREAM frames during unordered reads, unbounded connection-ID retirement growth, ACK_FREQUENCY peer-delay panic, stream reassembly memory-exhaustion guard bypass, zero-length DATAGRAM receive-buffer bypass). This was the cause of the 2026-10-13/14 daily security-audit failures.
- **rustls 0.23.45 → 0.23.46**: fixes RUSTSEC-2026-0346 through RUSTSEC-2026-0349 (`Debug` impls leaking TLS session secrets, buffered application data sent to outer server after ECH rejection, Brotli certificate decompression 1 GiB pre-authentication allocation, unauthenticated ServerHello downgrading later connections to classical key exchange). These advisories were published after the quinn-proto fix and would have failed the next scheduled audit run.

- **`has_unrestricted_private_allow` reported the wrong condition**: it flagged `Allow` rules with *unset* `private` (which the evaluator already neuters to deny-private) and missed `Allow` rules with explicit `private = true` (the actual SSRF surface). It now reports explicit private opt-ins not preceded by a blanket `deny private = true` rule, so the startup `policy.unrestricted_private` warning can actually fire on real configs.
- **Client SOCKS listener bound before scope check**: a forbidden non-loopback `--listen` address was briefly bound before `validate_socks_listener_scope` rejected it. IP-literal binds are now validated before the socket exists; the post-bind check remains as the second layer for hostnames.
- **Degraded-endpoint penalties survived SIGHUP reloads**: the process-global 180s cooldown cache is now cleared when a config reload is applied, so fixed endpoints are not penalized under the new config.
- **Shutdown could take ~2x `shutdown_timeout_seconds`**: session drains consumed the full timeout internally and the listener-level rejoin granted another full timeout on top. Both now share a single deadline computed at shutdown start.
- **`ReplayCache::check_and_insert` took a `now` parameter it ignored** (`let _ = now;`): removed the misleading parameter; retention stays monotonic.
- Removed dead public API (`FrameReader::limits`, `FrameReader::has_buffered_bytes`, `MIN_UDP_RELAY_FRAME_SIZE` — the TCP bound of 262 already covers UDP's 260) and deduplicated the TCP/UDP `validate_close_code` implementations into one shared check.
- Moved the misplaced half-close-drain doc comment from `handle_udp_open_frame` to `should_start_half_close_drain`, renamed the stale `review_settings_tests` module, and fixed assert messages that described the old buggy behavior instead of the expected one.
- Extracted the shared TCP/QUIC connection admission checks (`admit_connection`) instead of maintaining two near-duplicate accept paths.
- Centralized the tokio-rustls `"tls handshake eof"` sentinel behind `TLS_HANDSHAKE_EOF_MESSAGE` with a pinning test, and corrected the test's `ErrorKind` to the real `UnexpectedEof`.
- Documented that the dialer's fixed 60s target-socket keepalive is intentional (`TARGET_TCP_KEEPALIVE_SECONDS`; `tcp_keepalive_seconds` governs accepted carriers) and fixed the AGENTS.md misattribution of `100.100.100.200` (Alibaba Cloud, not GCP, metadata service).
- **CI determinism**: pinned `EmbarkStudios/cargo-deny-action` to the v2.1.1 commit SHA (which itself pins cargo-deny 0.20.2) and `actions/checkout` to the v5 commit SHA in all workflows, replacing the floating `@v2`/`@v4` tags that let the audit tool change under a frozen repo.

### Not changed (deliberate)

- The TLS *certificate* file is still not permission-checked (only the private key is): a certificate is public material by design — it is presented to every connecting peer during the handshake — so demanding `0600` on it provides no confidentiality benefit while breaking standard deployments (Kubernetes Secret mounts default to `0444`/`0644`, system trust stores are world-readable). An earlier revision of this change did enforce it and was reverted after the project's own e2e harness (which generates normally-permissioned certs) failed. AGENTS.md's certificate-permission line should be revisited with this in mind.

## [0.1.3] - 2026-09-06

### Security

- **IPv6 Authentication Rate Limiting & Prefix Aggregation**:
  - Aggregated authentication failure rate limiting by IPv6 `/64` network prefix (`RateLimitKey`), preventing rate limiter bypass across rotating IPv6 interface identifiers.
  - Preserved active bans during capacity eviction when reaching `MAX_ENTRIES`, preventing attackers from wiping legitimate bans through failure flooding.
  - Enforced `PRUNE_INTERVAL` throttling even under full capacity to prevent O(N) map scans and mutex contention under high failure rates.
- **Decoupled Stateless Auth Verification from ReplayCache Lock**:
  - Separated CPU-intensive credential lookups, HMAC-SHA256 calculations, and constant-time tag comparisons into stateless verification functions.
  - Eliminated server-wide handshake serialization by reducing the global `ReplayCache` mutex hold time strictly to nonce test-and-set insertion.
- **Sensitive File Permission Symlink Traversal Protection**:
  - Replaced `fs::metadata` with `fs::symlink_metadata` in `validate_sensitive_file_permissions` across client and server configurations.
  - Explicitly rejected symlinks on TLS private keys, client credentials, and CA certificates to prevent local file permission bypasses.
- **SSRF & Private IP Target Policy Safeguards**:
  - Added `has_unrestricted_private_allow` detection in `uk-policy` to identify allow rules matching private or loopback IP ranges without prior private denial rules.
  - Emitted actionable `policy.unrestricted_private` warnings during server config validation and startup to alert operators to potential SSRF / DNS rebinding exposures.
- **SOCKS Handshake Timeout Protection**:
  - Enforced `socks_handshake_timeout_seconds > 0` in client resource limit validation, preventing idle client connections from permanently holding semaphore connection slots.

### Changed

- **QUIC Client Endpoint Driver Cleanup**:
  - Removed unused runtime handle binding in `keep_endpoint_alive` and clarified background endpoint driver lifecycle.

## [0.1.2] - 2026-09-03

### Added

- **Production Helm Chart**: Fully configurable Kubernetes deployment chart (`deploy/helm/uncrowned-king`) with secure defaults, secret validation, and health/readiness probe configurations.
- **Architecture and Performance Tuning Guides**: Production deployment and operational tuning documentation (`docs/tuning.md`, `docs/architecture.md`).
- **Coalesced Frame Writing**: Batched carrier writes to reduce syscall overhead and maximize throughput under concurrent flow pressure.
- **Authentication IP Rate Limiting**: Sliding window rate limiting on connection attempts and authentication failures to protect against brute force, with max capacity eviction.
- **Configurable Relay Buffers**: Per-session and per-flow configurable buffer limits to control memory footprint under diverse network topologies.
- **Automated CI Matrix**: Cross-platform testing matrix, cargo-deny license and advisory scanning, and automated releases.

### Changed

- **Relay Engine Modularization**: Refactored monolithic client and server relay engines into focused, cohesive submodules (`carrier_writer`, `session_tasks`, `task_spawner`, `flow_control`, `target_writer`, `target_connect`, `udp_relay`).
- **Deduplicated HTTP Observability Probes**: Unified HTTP health check, readiness probe, and Prometheus metrics formatting in `uk-proto`.
- **`varint::decode` now rejects non-minimal encodings.** RFC 9000 permits a
  value to be encoded in any width at least as wide as the minimum; UK's parsers
  are deliberately strict (whitepaper §20), so one logical frame has exactly one
  wire form. This is a **receiver-side protocol tightening**: the bundled client
  and server only ever emit minimal encodings, so no bundled peer is affected,
  but a third-party implementation relying on that latitude will now be rejected
  with `InvalidVarint`. It also makes `MIN_TCP_RELAY_FRAME_SIZE` a real bound
  rather than one that assumed minimal encoding.

### Security

- **Authentication & Rate Limiting Hardening**:
  - Evict unbanned entries when rate limit capacity is reached to ensure active attacker tracking cannot be bypassed.
  - Offloaded dynamic security reload parsing to blocking tasks (`spawn_blocking`) to avoid Tokio event loop stalls.
  - Explicitly reject `UNREADABLE_CLOCK` sentinels in timestamp validation and credential activity checks.
  - Mitigated `key_id` timing oracle through constant-time dummy credential lookups and fixed-delay padding.
  - Fail closed on insecure or placeholder secrets in Helm charts.
- **Relay & Protocol Hardening**:
  - Protected against target decoding allocate-before-validate and `read_frame` memory preallocation OOM vulnerabilities.
  - Prevented server accept loop blocking on rejected handshakes and session invalidation blocking request paths.
  - Applied TCP keepalive to outgoing target connections on the server to prevent lingering half-open sockets.
  - Gracefully handle transient UDP socket receive errors and use non-blocking `try_send` to avoid head-of-line blocking under packet bursts.
- **Authentication no longer leaks key ids or the server clock through timing.**
  Credential lookup compared `key_id` with a short-circuiting `==` and returned
  before any HMAC, and the timestamp-skew check ran *before* tag verification —
  so an attacker with no credentials could distinguish a known key id from an
  unknown one and binary-search the server's clock. Lookup is now constant-time
  over all credentials, and the MAC runs before the activity and skew checks,
  against a per-process random dummy secret when nothing matches. Each probe
  still costs a full TLS handshake, so this was low severity.
- Secret-bearing types no longer derive `PartialEq`: `Credential`, `AuthResponse`
  and `AuthChallenge` now compare secrets, tags and nonces in constant time.
  Production code never compared them, but the derive left the trap in place for
  any future call site.
- Config files are read into a `Zeroizing` buffer, so the plaintext holding every
  credential secret is scrubbed after parsing rather than left in freed heap.
  (serde's own intermediate allocations remain out of reach.)
- A shared secret consisting of a single repeated byte is now rejected, and one
  whose byte diversity is implausibly low for its length is warned about at load.
  Neither can fire on a secret generated as `docs/key-management.md` prescribes.
- Replay-cache retention is now monotonic (`Instant`) rather than wall-clock, so
  an NTP step or VM resume can no longer flush the cache or over-retain.
- `Target::log_safe` now escapes space and `=`. A domain such as
  `a event=auth.bypass x` could otherwise forge extra fields in the default
  logfmt output; JSON logging was unaffected.

### Fixed

- **A hung server could stall every new SOCKS connection on the client.**
  `ClientSession::close` awaited `close_notify` with no deadline, and pruning a
  dead session ran that teardown *inline* on the flow-open path — twice while
  holding `connect_lock`. One blackholed carrier therefore blocked all new
  connections, and a config reload drove the same unbounded close from the
  listener's accept loop. Closing is now bounded by `shutdown_timeout_seconds`
  and pruning is reaped in the background, tracked so shutdown still waits for it.
  This is the client-side twin of the carrier-write deadline added for the server.
- **A stale connect result could be attached to a re-opened flow id.**
  `OpenCompleted`/`UdpOpenCompleted` carried no flow token, unlike every other
  flow lifecycle event, so a connect task finishing after its id was closed and
  re-opened had its stream wired into the *new* flow — connecting the client to a
  target it did not request on that open, and recording the wrong target in logs
  and metrics.
- **One unreachable UDP target no longer tears down the whole association.** A
  send failure propagated out of the relay loop, killing the SOCKS control
  connection and every other target's flow; an application using one UDP
  ASSOCIATE for all its DNS lost everything. The datagram is now dropped, which
  is what UDP semantics call for and matches the reliable path's per-flow
  handling.
- **Shutdown no longer truncates frames.** Carrier writes and target writes were
  raced against the shutdown signal in `select!`; `write_all` is not cancellation
  safe, so losing that race left an unknown-length prefix on the wire (or in the
  target's byte stream) while still reporting success. Both now complete, bounded
  by the carrier write deadline.
- **UDP relay now works against a server that offers DATAGRAM without the stream
  fallback.** Flow creation was gated on the stream-fallback setting alone, which
  conflated "can open a UDP flow" with "can carry UDP data on the stream" and
  disabled UDP entirely against such a peer, leaving the datagram path dead code.
  Payload sizing now reflects whichever data path the session actually has.
- **TCP keepalive on accepted carriers** (`tcp_keepalive_seconds`, default 60,
  `0` disables). A peer that vanished without closing left a half-open connection
  that no read or write deadline can observe, so its session slot was held until
  `idle_timeout_seconds` — five minutes by default. QUIC carriers are unaffected;
  quinn enforces its own transport idle timeout.
- Client TLS configuration is built once per CA path and shared, instead of being
  re-read and re-parsed on every dial and every QUIC endpoint attempt, and config
  validation during reload runs on a blocking thread. A slow or hung filesystem
  holding the CA bundle no longer stalls a runtime worker or the accept loop.
- `Target::decode` no longer risks a wrapping length check on 32-bit targets, and
  out-of-range CIDR prefixes are clamped rather than panicking or silently
  producing a wider mask than requested.

### Fixed

- **A client that stopped reading could pin its session slot for the lifetime of
  the process.** Carrier writes are serialised behind a single lock and had no
  deadline, so a peer that authenticated, started a download and then stopped
  reading parked the target-reader task inside `write_all` while holding that
  lock. The session loop could not make progress either — a `PING` would block
  it on the same lock — so the idle timeout never fired and the session, its
  slot, its target sockets and its buffered bytes were never released. Repeated
  `max_sessions` times, the server stopped admitting anyone.

  Carrier writes now honour `carrier_write_timeout_seconds` (new, default 30,
  `0` disables). The deadline covers the write itself rather than the wait for
  the lock, so queuing behind a large frame cannot fail a healthy session;
  exceeding it closes the session, which is both correct — an unknown-length
  prefix of the frame is already on the wire, so the carrier is unusable — and
  what releases the writers queued behind it. The session loop now watches for
  that condition and stops immediately instead of idling until its timeout.

  Session teardown was a second instance of the same leak: `shutdown_carrier_writer`
  took the carrier lock and awaited `close_notify` with no deadline, and the
  session permit outlives teardown — so a client that stopped reading pinned its
  slot from the close path even once the relay writes were bounded. Closing the
  carrier is now bounded by the same setting; a missed `close_notify` only costs
  the peer a clean shutdown signal, whereas blocking cost the server a slot.

### Security

- **Policy bypass via alternative IPv4-in-IPv6 encodings.** `private = true`
  rules and the unconditional cloud-metadata deny only recognised the
  IPv4-mapped form `::ffff:a.b.c.d`. A target encoded as NAT64
  (`64:ff9b::a.b.c.d`), IPv4-compatible (`::a.b.c.d`), or 6to4
  (`2002:a.b.c.d::`) was classified as public, so an authenticated client could
  reach RFC1918 hosts and `169.254.169.254` through a NAT64 gateway — a live
  SSRF path on IPv6-only and NAT64 deployments. Deny-side classification now
  decodes every embedded form; CIDR *matching* deliberately still uses only the
  strict mapped form, so allow-rules cannot be widened by this change. Also
  classifies `fec0::/10`, `2001:10::/28`, `3fff::/20`, `192.0.0.0/24`, and
  `192.88.99.0/24` as restricted.
- **Silently inert policy rules.** Patterns that can never match — glob
  wildcards such as `*.internal.corp`, URLs, and IP literals in `domain` /
  `domain_suffix` — passed `config-check` and then disabled the rule they were
  written for, typically a deny. They are now rejected at load.
- **UDP ASSOCIATE accepted relayed datagrams from any source.** RFC 1928 tells
  clients to send all-zero address/port when their UDP source is not yet known,
  and the client honoured that literally, letting the first datagram from any
  host claim the association. The source is now pinned to the SOCKS control
  connection's peer IP.
- **Unreadable system clock failed open.** `unix_now()` returned `0` when the
  host clock predated the Unix epoch, which is indistinguishable from a valid
  timestamp: skew checks passed and credentials with `not_after` were treated as
  unexpired. The server now refuses to authenticate, and `try_unix_now()`
  reports the condition explicitly.
- **Unvalidated `auth_skew_seconds`.** `u64::MAX` disabled timestamp freshness
  entirely and `0` broke authentication, both accepted silently. Now bounded,
  and cross-validated so `replay_cache_window_seconds` covers twice the skew.
- **`policy_path` had no permission check**, unlike the config and private key,
  so a group-writable file or a planted symlink could rewrite the entire access
  ruleset and be loaded live by SIGHUP. It must now be owner-writable only, and
  the check uses `symlink_metadata` so a symlink cannot dodge it.

### Fixed

- **Frame desync tore down sessions under ordinary concurrent traffic.**
  `read_frame` kept partially decoded state inside its future, but the server's
  session loop used it as a `tokio::select!` branch. Any other branch firing
  mid-frame — `FlowEvent::Activity` does so on every target read — dropped that
  future and destroyed the bytes it had already taken from the carrier, so
  parsing resumed part-way through a frame. Reproduced 100% of the time with
  eight concurrent bidirectional flows on a default config (`unsupported
  protocol version 9/45/241/244`, then session teardown). Worse, a peer could
  aim the resynchronisation at its own relayed payload and have it parsed as a
  control frame, forging `TCP_CLOSE`/`UDP_CLOSE` for *other* flows on the same
  session. Added `uk_proto::FrameReader`, which buffers in the struct rather
  than the future and is cancellation safe; the server's session loop uses it.
  The free `read_frame` remains for the handshake paths, now documented as not
  cancellation safe.
- **Unbounded task spawn from a duplicate `TCP_CLOSE`.** The half-close drain
  timer was guarded on the target read side alone, so every repeated
  `TCP_CLOSE(NORMAL)` for an already half-closed flow spawned another 30-second
  timer task — roughly 7 bytes of input per task, with no bound.
- **A failed flow event skipped session teardown.** That arm used `?` where its
  siblings used `break Err`, returning past the block that closes target flows,
  drains spawned tasks, and shuts the carrier down cleanly.
- **A stale UDP reader could retire a re-opened flow.** `UdpReadClosed` carried
  no flow token, unlike every TCP lifecycle event, so a reader finishing after
  its flow id was closed and re-opened tore down the new association.
- **Concurrent SOCKS connections failed far below configured capacity.** Session
  selection read `flow_count()` and only reserved a slot several awaits later,
  so a burst piled onto one session; the losers were rejected outright and the
  pool never grew. Admission is now an atomic semaphore reservation released on
  every failure path. A full per-session `max_udp_flows` still refuses rather
  than dialling another carrier, so the server's limit cannot be worked around.
- **A rejected credential was replayed to every endpoint.** A definitive
  `AuthFailed` no longer falls through to the next carrier, which previously
  cost a full extra handshake per SOCKS connection. Transport errors during the
  auth exchange remain retryable.
- **Graceful shutdown truncated in-flight data behind a clean FIN.**
  `write_all` is not cancellation safe, so racing it against shutdown left an
  unknown-length prefix on the local socket and then closed it normally — the
  application saw a clean EOF on a truncated stream. The write is now resumed
  rather than abandoned, bounded by a grace period after which the flow fails
  instead of reporting success, and already-buffered frames are flushed first.
- **An authenticated session leaked if the connect future was cancelled.** Three
  awaits sat between `ClientSession::connect` and pooling the session; a drop in
  that window left the carrier and three tasks alive for the process lifetime,
  invisible to shutdown. Ownership now tears the session down on drop.
- **Replay-cache work was O(n) under a process-global lock**, so every handshake
  scanned up to 65 536 entries twice once the cache saturated. Pruning and
  eviction are now amortised O(1) via an insertion-order queue.
- Frame payload buffers are no longer allocated at the peer-declared size before
  any payload arrives; capacity grows in bounded steps as bytes actually land.
- SOCKS5 reply codes are accurate: `CommandNotSupported` when the server offers
  no UDP relay, and `GeneralFailure` rather than `HostUnreachable` for a
  malformed target. An oversized first datagram no longer opens a UDP flow it
  immediately abandons.
- **Every documented deployment path now actually starts.** All of the failures
  below stem from the startup check that rejects a config file or private key
  with any group/other permission bit set (`mode & 0o077 != 0`), plus the
  client's refusal to open a non-loopback SOCKS5 listener without
  `--allow-non-loopback`.
  - **Docker**: the client image's `CMD` binds `0.0.0.0:1080` but omitted
    `--allow-non-loopback`, so the container exited immediately with
    "refusing unauthenticated SOCKS5 listener". The flag is now passed, with a
    comment explaining that `0.0.0.0` inside the container's network namespace
    is not the exposure — publishing the port is.
  - **systemd units**: the documented `install -m 0640` for `server.toml`,
    `client.toml`, and `server-key.pem` produced an unstartable service. Both
    units now specify `0600` and state why `0640` fails.
  - **Kubernetes**: the Secret was mounted at `defaultMode: 0400` under
    `fsGroup: 65532`, which the kubelet projects as `root:65532` mode `0440` —
    rejected by the server; dropping `fsGroup` yields `0400 root:root`, which
    uid 65532 cannot read at all. The manifest now stages the Secret and policy
    ConfigMap into a memory-backed `emptyDir` at mode `0600` via an
    `initContainer`, and the server mounts only that copy.
  - **Kubernetes**: removed the `subPath` mounts, which are never updated when
    the Secret/ConfigMap changes and so silently defeated SIGHUP hot-reload.
    Applying changed credentials, policy, or TLS material now requires
    `kubectl rollout restart`, documented in the manifest, `deploy/README.md`,
    and `docs/key-management.md`.
- **`--version` reported `0.1.0` on the 0.1.1 release**: the workspace version
  was never bumped. Bumped to `0.1.1`, and `release.yml` now fails the release
  if the pushed tag disagrees with the workspace version.
- **Docs contradicted the code**: `docs/operations.md` and `docs/launch-gate.md`
  offered `0640` as an acceptable mode for secrets and keys. Corrected to `0600`
  everywhere.

### Changed

- systemd units add `AF_UNIX` and `AF_NETLINK` to `RestrictAddressFamilies`.
  The published static musl binaries do not need them, but a glibc build — what
  the units' own install steps produce — cannot resolve hostnames via
  `nsswitch.conf` backends (systemd-resolved/nscd) or do source-address
  selection without them.
- Kubernetes pod spec sets `automountServiceAccountToken: false`; nothing in the
  pod talks to the API server.
- README's Docker section publishes the SOCKS5 port to loopback and warns that
  `-p 1080:1080` exposes an unauthenticated proxy on every host interface.
- Corrected the `Dockerfile` comment that claimed dependency compilation was
  cached across source-only changes; the following `COPY crates` makes that
  false.

## [0.1.1] - 2026-07-18

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

[Unreleased]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/v0.1.3...v1.0.0
[0.1.3]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/HappyLeslieAlexander/Uncrowned-King/releases/tag/v0.1.0
