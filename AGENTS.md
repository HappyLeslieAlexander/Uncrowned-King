# Uncrowned King — Development Guidelines & Production Guardrails

This document establishes the non-negotiable architectural invariants, security policies, and deployment rules for the `Uncrowned King` (UK) codebase (`v2.x`). All agents and contributors must strictly adhere to these principles.

---

## 0. Workspace Layout, Toolchain & CI Gates

- **Workspace Crates** (`edition = "2024"`, MSRV `1.85.0`):
  - `crates/uk-proto`: wire framing, canonical varints, settings negotiation, observability bind validators.
  - `crates/uk-auth`: constant-time HMAC-SHA256 authentication, TLS exporter binding, replay cache.
  - `crates/uk-policy`: secure-by-default egress access control (`PolicySet`, `PolicyRule`, `Cidr`).
  - `crates/uk-mask`: opt-in below-TLS/QUIC transport masking (`MaskKeys`, `MaskedStream`, `MaskedUdpSocket`, `ReplayRegistry`).
  - `crates/uk-server`: TLS/TCP & QUIC carrier server, masking admission, rate limiter, relay engine, SIGHUP reload, Prometheus observability.
  - `crates/uk-client`: SOCKS5 ingress, carrier pool/failover, masked TLS/QUIC connectors, SIGHUP reload.
- **Workspace Lints**: `unsafe_code = "forbid"`, `missing_docs = "warn"`, and `clippy::pedantic` (all CI checks run with `-D warnings`).
- **Required Verification Gates** (mirror `.github/workflows/ci.yml` and `.github/workflows/security.yml`):
  - `cargo fmt --all --check`
  - `cargo check --workspace --locked`
  - `cargo test --workspace --locked`
  - `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`
  - `cargo deny check` and `cargo audit --file ./Cargo.lock`
  - `./scripts/helm-config-check.sh target/debug` (whenever config fields or Helm templates change)
  - `./scripts/interop-curl.sh` (end-to-end TLS & QUIC interop check)

---

## 1. Code Integrity & Safety Invariants

- **Strict Zero Unsafe (`unsafe_code = "forbid"`)**:
  - The workspace strictly prohibits `unsafe` code across all crates.
  - Never introduce `unsafe` blocks, `std::mem::transmute`, unchecked pointer dereferences, or foreign functions without explicit workspace-wide policy exemption.

- **Constant-Time Cryptography & Anti-Side-Channel**:
  - All HMAC verification and Key ID matching in `uk-auth` and `uk-mask` must execute in constant time (`subtle::ConstantTimeEq`).
  - When an unknown `key_id` is supplied in `uk-auth`, execute a dummy HMAC calculation to maintain constant execution duration and avoid timing leaks.
  - Long-lived secret and derived key material (`MaskKeys`, credentials) must be wrapped in `zeroize::Zeroizing` so secrets are wiped on drop.

- **Canonical Varint & Bounded Memory Allocation**:
  - Frame headers and payload length prefixes in `uk-proto` must strictly adhere to RFC 9000 §16 canonical Varint encoding (reject non-minimal encodings).
  - Stream and frame readers must read payloads in bounded chunks (e.g. 256 KB `READ_RESERVE_CHUNK`) to prevent memory exhaustion DoS from maliciously inflated headers.
  - **Early Header Bounds Validation**: Frame and stream readers must validate fixed-header fields (`FrameType::try_from`, wire length minimums) *before* decoding variable-length integers (varints) or allocating buffers.
  - **Pre-Allocation Bounds Checking**: Any dynamic wire field with a length prefix (e.g. `key_id`, target domains) must strictly validate length limits *before* calling buffer `reserve()` or allocating memory.

---

## 2. Security & Policy Enforcement Guardrails

- **Secure-by-Default Access Control (`uk-policy`)**:
  - Any `Allow` rule in `PolicyRule` must default to rejecting private/loopback IPs (`private = Some(false)`) unless explicitly configured with `private = true`. The restricted-address classifier must cover the full IPv4 `0.0.0.0/8` "this network" block (Linux routes it to loopback), not only exact `0.0.0.0`.
  - Cloud provider metadata service addresses (AWS/GCP `169.254.169.254`, Alibaba Cloud `100.100.100.200`, Azure WireServer `168.63.129.16`, AWS IPv6 `fd00:ec2::254`) must be permanently rejected before evaluating any user-defined rules.
  - Domain validation must strictly reject IP literal strings (`"127.0.0.1"`, `"::1"`) passed as `Target::Domain` to prevent policy bypass.
  - **Dual-Stack Observability Canonicalization**: Observability endpoint validators must canonicalize IPv4-mapped IPv6 addresses (e.g. `::ffff:0.0.0.0`) and reject all wildcard bindings (`0.0.0.0`, `[::]`).

- **Brute-Force Defense in Depth (`uk-server` rate limiter)**:
  - Per-source failure aggregation (IPv4 address, IPv6 `/64`) must never evict **active bans** when the tracking table saturates.
  - **Escalating Bans**: each repeat ban of the same source must at least double the ban duration (`ban_secs × 2^n` per prior ban), capped at 30 days. The ban count survives ban-expiry resets and decays only when the entry is pruned after quiet periods.
  - **Global Failure Governor** (`auth_rate_limit_global_failures`, default `10 × auth_rate_limit_failures`, `0` disables): a cross-source sliding-window failure count that engages *enhanced mode* — failures count double toward per-source bans and admission paths apply their maximal rejection posture (masking drain pinned to the full admission timeout). Memory must stay bounded (≤ `GLOBAL_BUCKET_COUNT + 1` time buckets) regardless of window size.
  - Auth replay rejections (`ReplayCache`) and masking replay rejections are accounted in the distinct `handshake_failures_total{reason="replay"}` bucket, never merged into `reason="auth"`; both still count into the failure limiter.

- **Atomic Reload & Config Synchronization**:
  - SIGHUP configuration reloads must atomically swap TLS/QUIC acceptors and authentication state for *new* connections without interrupting or modifying already accepted connection contexts.
  - Any newly added server or client configuration field must stay synchronized across `config.rs`, `ensure_reload_compatible` / `reload_static_limits` (for restart-only settings), Helm configmap allowlists (`deploy/helm/uncrowned-king/templates/{server,client}-configmap.yaml`), and `scripts/helm-config-check.sh`.

---

## 3. Concurrency, Transport & Lifecycle Management

- **Graceful Shutdown & Connection Draining (`uk-server`)**:
  - Server shutdown upon `SIGTERM` or `Ctrl+C` must execute a graceful drain phase: stop accepting new connections, signal downstream clients, and allow active flows a configurable timeout period (default 30s) to terminate cleanly before hard cancellation.
  - Never drop reader/writer tasks instantaneously without draining active flows.
  - **Relay Flow Table Hygiene**: TCP and UDP relay workers must immediately call `remove_flow_slot()` upon target dial or relay failure, never leaving dangling active flow tracking entries.

- **Transport Resilience & Reconnection Discipline (`uk-client`)**:
  - Reconnection logic must implement exponential backoff with randomized jitter. Avoid fixed-interval reconnection loops (e.g. static 250ms) to prevent thundering herd storms against recovering servers.
  - Cache carrier availability: if QUIC/UDP is unreachable or filtered, remember degraded state to avoid repetitive 10-second handshake timeouts.
  - **Socket Leak Prevention**: Multi-address dial loops must immediately close failed or unused candidate sockets before trying next addresses.
  - **Draining Session Exclusion**: Connection pool dispatchers (`first_live_session`) must strictly exclude sessions in `Draining` state, routing new application streams only to active carriers.

- **Carrier Disconnect Target Flow Flushing (`uk-server`)**:
  - When an authenticated carrier disconnects or encounters an unrecoverable transport error, the server must mark target flows half-closed before initiating drain (`target.mark_target_to_client_closed()` and `target.close_client_to_target()`), ensuring all in-flight client payload bytes queued in relay buffers flush cleanly to targets rather than triggering instantaneous drop aborts.

- **QUIC Transport & Stateless Retry Discipline**:
  - QUIC client transport configs must explicitly configure active keep-alive (e.g. 15s) and bounded idle timeout (e.g. 60s) to keep stateful firewall NAT mappings alive on idle connections.
  - Server QUIC listeners must enforce stateless source address validation (`incoming.retry()`) against unvalidated remote addresses before allocating handshake resources or permits.
  - QUIC connection receive window must always be validated to be greater than or equal to stream receive window (`quic_connection_receive_window >= quic_stream_receive_window`).

- **Transport Masking Discipline (`uk-mask`, `uk-server`, `uk-client`)**:
  - Masking is **opt-in** (`[masking]`, default off) and sits strictly **below** TLS/QUIC: it must never touch the TLS/QUIC session state, exporter binding, ALPN verification, or 0-RTT policy. TCP masking (`masking.enabled`) and QUIC masking (`masking.quic`) are independent — TCP prelude admission must only activate when `masking.enabled` is `true` (never merely because a `[masking]` section or `masking.quic = true` is present).
  - Prelude verification must scan **all** credentials in a padded constant-cost loop with **no early exit**; tag comparison must use `subtle::ConstantTimeEq`; every rejection must collapse into one indistinguishable error (`MaskError::PreludeRejected`).
  - **Tag-Before-Report Ordering**: prelude decoding must compute and compare the authentication tag *before* deciding any rejection — even the zero-counter check happens only after the full HMAC — so no cheap check can answer ahead of the cryptographic one (mirrors the dummy-HMAC discipline in `uk-auth`).
  - **Pre-Admission Concurrency Limits**: masked TCP listeners must bound unauthenticated concurrency (global and per-source IPv4 / IPv6 `/64` slots) immediately after `accept()`, before prelude reading/draining and before taking `handshake_permits`, preventing Slowloris or distributed probes from exhausting file descriptors or tasks.
  - **Silent `ClientHello` Parsing & Two-Phase Replay Commit**: on masked TCP connections, parse the `ClientHello` via `rustls::server::Acceptor` with a strict `64 KiB` cumulative buffer limit so malformed hellos and TLS alerts emit **zero** response bytes, never commit the replay counter, count into `AuthRateLimiter`, and drain under the uniform silent rejection posture. Atomically commit `(identity, counter)` only after a valid `ClientHello` parses and strictly before `StartHandshake::from_parts` writes `ServerHello`.
  - **Zero-Allocation Replay Registry**: `ReplayRegistry` must use preallocated fixed-capacity storage (ring array + open-chained hash buckets with `RandomState`) and word-level bitmap shifting so steady-state commits and FIFO evictions perform zero heap allocations; client counter allocation (`ClientSequence::allocate`) must saturate via CAS without wrapping.
  - **Full-Handshake `SO_LINGER=0` & Shared Deadline**: set `SO_LINGER=0` immediately upon masked `accept()` and track a single shared absolute `deadline = accepted_at + handshake_timeout` across prelude, TLS, ALPN, and `AUTH_RESPONSE`. Every pre-auth rejection drains under a bounded budget (4 KiB / 64 reads) with uniform jittered dwell (`[1/2, 1] × admission_timeout`, pinned to full timeout in enhanced mode) and closes abortively (`RST`); normal linger semantics are restored only after application authentication succeeds (with deadline checks before and after clearing `SO_LINGER`). `handshake_timeout_seconds = 0` must never produce an instant `Duration::ZERO` masking timeout.
  - **TCP Stream Masking & Client Coalescing**: `MaskedStream` must bound per-write chunks (`MAX_WRITE_CHUNK = 64 KiB`), check write readiness before encrypting, use single-pass `try_apply_keystream_b2b`, rewind keystreams on partial/pending writes, and clamp reads/writes to `STREAM_LIMIT`. Client `MaskedStream` should coalesce its 76-byte prelude+nonce with the first encrypted `ClientHello` write into a single send.
  - **Masked QUIC Discipline**: masked QUIC endpoints are pinned to one designated credential (`masking.quic_key_id`); both MTU discovery (`1452 - 12 = 1440`) and `EndpointConfig::max_udp_payload_size` (reduced by 12 bytes) must account for the per-segment nonce. `MaskedUdpSocket` must separate send and receive locks, bound stack-allocated `IoSliceMut` slices by `bufs.len().min(meta.len()).min(BATCH_SIZE)`, decrypt in a single pass via `try_apply_keystream_b2b`, silently drop unsupported QUIC versions, and yield (`cx.waker().wake_by_ref(); Poll::Pending`) when a receive batch filters to `produced == 0` so invalid-packet floods cannot starve the runtime. Rate-limited or permit-exhausted masked QUIC attempts must be silently dropped (`incoming.ignore()`).
  - Changing the `[masking]` section requires a restart; credential reloads rotate TCP mask keys for new connections only. Masking rejections count into the `auth_rate_limit_*` failure limiter.

---

## 4. Operational Readiness & Deployment Standards

- **Strict File Permissions (`mode & 0o077 == 0`)**:
  - Server strictly enforces that configuration files and private keys have no group or other permissions (e.g. `0600` or `0400`). Certificates are public handshake material and are intentionally exempt from this check.
  - **Kubernetes / Helm Manifests**: ConfigMaps are mounted with `0644` by default; deployment templates must use an `initContainer` to copy and `chmod 0600` configuration files into a shared emptyDir volume before the main container starts.
  - **Zero Plaintext & Fail-Closed Secrets**: Authentication keys and private keys must never be placed in plain `ConfigMap` templates. Always use Kubernetes `Secret` resources, and fail closed in Helm templates if secret values are missing, empty, or placeholders. Credential generation templates must strictly enforce non-empty `key_id` (or `id`) alongside secrets to prevent silent generation of invalid empty identifiers that crash services at startup. CI assertion tests validating template rejection must verify both server and client fail-closed paths and maintain synchronized error pattern substrings.
  - **Downward API IP Binding**: In containerized deployments, unauthenticated metrics and health endpoints must bind to `status.podIP` via Downward API, never wildcards.
  - **Dual-Stack NetworkPolicy Hardening & Syntax Invariants**:
    - When NetworkPolicies are enabled, egress rules must support dual-stack clusters by including both IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`) blocks. Both address families must strictly exclude private/loopback/link-local ranges (RFC 1918, `fc00::/7`, `fe80::/10`, `::1/128`, `::ffff:0:0/96`) and cloud metadata endpoints (AWS/GCP `169.254.169.254`, Azure `168.63.129.16`, Alibaba `100.100.100.200`, AWS IPv6 `fd00:ec2::254/128`).
    - **Prohibit Empty Peer Lists (`from: []` / `to: []`)**: In Kubernetes NetworkPolicy semantics, an empty peer list matches zero peers, resulting in total traffic denial (blackhole). Never specify `from: []` or `to: []` when intending to allow unrestricted peer access to ports. To permit all peers on specific ports, omit the `from`/`to` key entirely and declare `ports:` directly under the rule item.
    - **Dual-Component NetworkPolicy Parity**: When `networkPolicy.enabled` is true, policy resources must be generated for both Server and Client (when `client.enabled: true`), permitting cluster-internal SOCKS5 ingress, DNS egress, and carrier transport between Client and Server.
  - **GPG-Signed Releases & Version Consistency**: Release commits and git tags must be cryptographically signed (`git commit -S`, `git tag -s`). Version bumps must atomically synchronize root `Cargo.toml`, `Cargo.lock`, `Chart.yaml`, `values.yaml` (both server and client image tags), `deploy/kubernetes/uncrowned-king-server.yaml`, `deploy/kubernetes/uncrowned-king-client.yaml`, and `CHANGELOG.md` (both the release header and the bottom compare links).
  - **Standalone Manifest Parity**: Standalone Kubernetes manifests in `deploy/kubernetes/` must maintain 100% security and deployment parity with the Helm chart, including `PodDisruptionBudget`, dual-stack `NetworkPolicy` (with cloud metadata and RFC 1918 exclusions), non-root security contexts, and `automountServiceAccountToken: false`.

- **Immutable Supply Chain Pinning**:
  - All third-party GitHub Actions in CI/CD release and security workflows (including `taiki-e/install-action` for `cargo audit --file ./Cargo.lock` and `EmbarkStudios/cargo-deny-action`) must be pinned to immutable 40-character commit SHAs with trailing version comments (e.g. `uses: action@<sha> # vX.Y.Z`).
  - Dockerfile base images and deployment manifest `initContainer` images (e.g., config-staging busybox images) must be pinned to immutable `@sha256:` content digests rather than floating tags.

- **Prometheus & Observability Standards**:
  - All metrics exported via the `/metrics` endpoint must strictly follow Prometheus text format conventions (including `# HELP` and `# TYPE` declarations).
  - Internal management and metrics endpoints (`:9090`) must bind to internal cluster networks only and never be exposed on public LoadBalancer services.

---

## 5. Testing & Verification Discipline

- **Deterministic Asynchronous Task Completion**:
  - Asynchronous tests must never rely on fixed short wall-clock sleeps (e.g. `sleep(20ms)`) to await background task completion or `JoinSet` abortion.
  - Always await `join_next()` or drain tasks with an explicit poll-with-timeout loop (`while !tasks.is_empty() { tasks.join_next().await }`) to prevent flaky test failures on loaded CI runners.
