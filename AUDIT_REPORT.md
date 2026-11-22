# Uncrowned King — Comprehensive Codebase Security & Architectural Invariants Audit Report

**Date**: 2026-10-26  
**Auditor**: Teamwork Security & Quality Audit Specialist  
**Target Crates**: `uk-proto`, `uk-auth`, `uk-policy`, `uk-mask`, `uk-server`, `uk-client`  
**Baseline Release**: v2.0.0 (`Cargo.toml`)  
**Standard**: `AGENTS.md` (Production Guardrails & Architectural Invariants)

---

## 1. Executive Summary

A full-spectrum architectural and security verification audit of the Uncrowned King (UK) codebase was conducted across all six core workspace crates (`uk-proto`, `uk-auth`, `uk-policy`, `uk-mask`, `uk-server`, `uk-client`). The objective was to audit the codebase against the non-negotiable architectural invariants codified in `AGENTS.md`, identify state-machine edge cases, race conditions, memory bounds defects, and protocol parsing vulnerabilities, and provide deterministic automated test suites (PoCs) along with production hardening remediation patches.

### Findings Breakdown by Severity

| Severity Level | Finding Count | Key Focus Areas |
|:---|:---:|:---|
| **Critical** | 1 | Bit-shift direction inversion breaking transport masking replay window protection |
| **High** | 7 | SIGHUP MTU drop, oversized control frame allocations, frame decoder stream desync, session drain flow flush inversion, rate limit table saturation and history erasure, commit gate rate limiter bypass |
| **Medium** | 12 | Metric accounting misclassifications, timing dwell truncation on EOF, IPv4-mapped address CIDR matching, replay cache capacity eviction, memory governor floor division, flow slot leaks on dial failure, SIGHUP limit checks, client QUIC accept hang, header truncation bounds, decoder loops |
| **Low** | 3 | Challenge/response length minimum checks, pre-validation buffer consumption, ORCHIDv2 prefix classification |
| **Total** | **23** | **100% Deterministically Verified with Automated PoC Tests** |

All 23 findings have been cataloged with root cause analyses, trigger call graphs, deterministic automated Rust test cases, and exact remediation patches. Baseline workspace integrity remains fully intact (`cargo check --all-targets` and `cargo test --workspace --locked` pass with zero warnings and zero compiler errors).

---

## 2. Invariant Verification Matrix across Workspace Crates

| Architectural Invariant (`AGENTS.md`) | Target Crates | Audit Assessment | Verification Status & Findings |
|:---|:---|:---:|:---|
| **Strict Zero Unsafe (`unsafe_code = "forbid"`)** | All 6 Crates | **Verified Compliant** | Workspace-wide `#![forbid(unsafe_code)]` enforced in all crates; no `unsafe` blocks, transmutes, or FFI bindings exist. |
| **Constant-Time Cryptography & Dummy MAC** | `uk-auth`, `uk-mask` | **Verified Compliant** | `subtle::ConstantTimeEq` used for HMAC tags and Key IDs; dummy HMAC calculated on unknown keys to avoid timing side channels. |
| **Canonical Varint Encoding (RFC 9000 §16)** | `uk-proto` | **Verified Compliant** | Canonical minimal representations strictly enforced; non-minimal encodings rejected. |
| **Early Header Bounds & Pre-Allocation Checking** | `uk-proto`, `uk-auth` | **Defects Identified** | `FINDING-03` (control frame payload lengths), `FINDING-04` (destructive decode on truncation), `FINDING-17` (header 4 vs 6 byte underrun), `FINDING-18` (read_frame version check delay), `FINDING-19` (settings decode loop), `FINDING-20` (auth response allocation before tag), `FINDING-21` (auth challenge truncation), `FINDING-22` (tcp open consumption). |
| **Secure-by-Default Access Control & Cloud Metadata** | `uk-policy` | **Verified Compliant** | Default allow rules enforce `private = Some(false)`; full `0.0.0.0/8` block covered; cloud metadata IMDS IPs (AWS/GCP/ECS, Alibaba, Azure WireServer, AWS IPv6) permanently rejected before rule evaluation. |
| **Domain IP Literal Rejection & Canonicalization** | `uk-proto`, `uk-policy` | **Defects Identified** | IP literal strings rejected in domain parsing; however, `FINDING-11` demonstrates `::/0` matches IPv4-mapped addresses, and `FINDING-23` identifies missing ORCHIDv2 classification. |
| **Rate Limiter Defense in Depth & Escalating Bans** | `uk-server` | **Defects Identified** | `FINDING-06` (prune destroys ban escalation history), `FINDING-07` (saturation eviction ignores expired bans), `FINDING-13` (governor floor division exceeds bucket limits). |
| **Atomic Configuration Reload & State Isolation** | `uk-server` | **Defects Identified** | SIGHUP swaps credentials cleanly for new connections; however, `FINDING-02` shows reload drops QUIC 1440 MTU clamp, and `FINDING-15` omits global failure threshold from static limit validation. |
| **Graceful Shutdown & Target Flow Half-Close Flushing** | `uk-server` | **Defects Identified** | `FINDING-05` demonstrates `close_session` calls `shutdown.close()` before `close_target_flows`, causing relay workers to drop buffered data; `FINDING-14` leaks flow slots when open failure frame delivery fails. |
| **Transport Masking Boundary & Two-Phase Replay Commit** | `uk-mask`, `uk-server` | **Defects Identified** | Masking sits cleanly below TLS/QUIC; however, `FINDING-01` demonstrates critical bitshift inversion in `ReplayEntry::advance`, `FINDING-08` shows commit gate replay collisions bypass rate limiter, `FINDING-09` misclassifies replay metrics as auth, and `FINDING-10` leaks timing oracle on EOF. |
| **QUIC Connection Lifecycle & Timeout Discipline** | `uk-client`, `uk-server` | **Defects Identified** | QUIC keepalive configured; however, `FINDING-16` demonstrates unbounded `accept_bi()` hang in client connect. |

---

## 3. Comprehensive Vulnerability Catalog

---

### FINDING-01: `uk-mask::ReplayEntry::advance` Window Bit Shift Inversion Breaks Replay Protection
- **Severity**: **Critical** (CVSS: 8.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
- **Affected Crate & File**: `crates/uk-mask/src/replay.rs:72-85`
- **Root Cause & Trigger Chain**:
  `ReplayEntry` maintains a 1024-bit sliding window (`seen: [u64; WINDOW_WORDS]`) of observed counters below `highest`. When a fresh counter $C_{\text{new}} > \text{highest}$ is committed, the window must slide down by $\Delta = C_{\text{new}} - \text{highest}$. An already observed counter at distance $d$ must now be tracked at distance $d + \Delta$ (shifted rightward toward older distance).
  However, `advance` implements:
  ```rust
  for target in 0..REPLAY_WINDOW {
      let source = target + advance;
      if source < REPLAY_WINDOW && self.bit_is_set(source) {
          shifted[(target / 64) as usize] |= 1 << (target % 64);
      }
  }
  self.seen = shifted;
  ```
  Here `source = target + advance`, shifting bits **leftward** toward distance 0. Because `source >= advance > 0`, bit 0 (representing the previous `highest` counter) is never checked and is completely discarded. When a client commits counter 100 and then advances to counter 105, counter 100's record in the window is wiped. An adversary replaying counter 100 is subsequently accepted, destroying anti-replay protection.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_01_replay_advance_bitshift_inversion`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_01_replay_advance_bitshift_inversion`
- **Remediation Patch**:
  In `crates/uk-mask/src/replay.rs`, invert the shift assignment:
  ```rust
  fn advance(&mut self, advance: u64) {
      if advance >= REPLAY_WINDOW {
          self.seen = [0; WINDOW_WORDS];
          return;
      }
      let mut shifted = [0; WINDOW_WORDS];
      for source in 0..REPLAY_WINDOW {
          let target = source + advance;
          if target < REPLAY_WINDOW && self.bit_is_set(source) {
              shifted[(target / 64) as usize] |= 1 << (target % 64);
          }
      }
      self.seen = shifted;
  }
  ```

---

### FINDING-02: `uk-server` SIGHUP Reload Drops QUIC Masked MTU Discovery Cap
- **Severity**: **High** (CVSS: 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Affected Crate & File**: `crates/uk-server/src/lib.rs:838-848`, `crates/uk-server/src/quic.rs:111-124`
- **Root Cause & Trigger Chain**:
  At startup, `quic::server_config_with_transport_params_masked` is called with `masked: true`, capping Quinn's MTU discovery upper bound to $1452 - 12 = 1440$ bytes to prevent masked datagrams exceeding 1500-byte MTU boundaries.
  During SIGHUP configuration reload (`apply_security_reload`), line 840 calls `quic::server_config_with_transport_params(...)`, which hardcodes `masked: false`. This replaces the active QUIC server configuration with one permitting 1500-byte discovery. Probe packets exceeding 1440 bytes cause intermediate path fragmentation or silent packet loss on PPPoE and tunnel interfaces.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_02_sighup_reload_drops_quic_masked_mtu_cap`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_02_sighup_reload_drops_quic_masked_mtu_cap`
- **Remediation Patch**:
  In `crates/uk-server/src/lib.rs:838-848`, pass `mask_keys.is_some()` to `quic::server_config_with_transport_params_masked`:
  ```rust
  let quic_config = if quic_endpoint.is_some() {
      let quic_tls_config = tls::server_config_from_memory(certs, key)?;
      let is_masked = mask_keys.is_some();
      Some(quic::server_config_with_transport_params_masked(
          quic_tls_config,
          idle_timeout(candidate.idle_timeout_seconds()),
          candidate.quic_stream_receive_window(),
          candidate.quic_connection_receive_window(),
          is_masked,
      )?)
  } else {
      None
  };
  ```

---

### FINDING-03: `uk-proto` Control Frame Unchecked Payload Length Leads to Slowloris Buffer Bloat
- **Severity**: **High** (CVSS: 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Affected Crate & File**: `crates/uk-proto/src/frame.rs:165-195`, `crates/uk-proto/src/io.rs:80-92, 188-209`
- **Root Cause & Trigger Chain**:
  `FrameHeader::decode` validates `length` only against `limits.max_frame_size` (default 65,536 bytes, configurable up to 16 MB). Control frames have strict fixed or bounded payload sizes (`TcpClose` and `UdpClose` are strictly 2 bytes; `TcpOpen` is 10..=261 bytes; `UdpOpen` is 8..=259 bytes).
  An attacker can send a `TcpClose` frame header declaring `length = 65536`. `read_frame` and `FrameReader` pre-allocate a 256 KB buffer (`READ_RESERVE_CHUNK`) and await 65 KB from the socket, stalling reader tasks and causing unbounded memory bloat under slowloris delivery.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_03_control_frame_unchecked_payload_length`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_03_control_frame_unchecked_payload_length`
- **Remediation Patch**:
  In `crates/uk-proto/src/frame.rs:180`, enforce structural bounds per frame type:
  ```rust
  match frame_type {
      FrameType::TcpClose | FrameType::UdpClose if length != 2 => {
          return Err(ProtocolError::InvalidFrame("invalid close frame payload length"));
      }
      FrameType::TcpOpen if !(10..=261).contains(&length) => {
          return Err(ProtocolError::InvalidFrame("invalid tcp open frame payload length"));
      }
      FrameType::UdpOpen if !(8..=259).contains(&length) => {
          return Err(ProtocolError::InvalidFrame("invalid udp open frame payload length"));
      }
      FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit
          if length == 0 || length > 8 =>
      {
          return Err(ProtocolError::InvalidFrame("invalid status frame payload length"));
      }
      _ => {}
  }
  ```

---

### FINDING-04: `uk-proto::Frame::decode` Destructively Consumes Header from Buffer on Truncated Payload
- **Severity**: **High** (CVSS: 7.2 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
- **Affected Crate & File**: `crates/uk-proto/src/frame.rs:237-246`
- **Root Cause & Trigger Chain**:
  `Frame::decode` runs `FrameHeader::decode(src, limits)?` directly against `src`, advancing the buffer by 6+ bytes. It then checks `if src.remaining() < length { return Err(ProtocolError::Truncated); }`. If the payload is incomplete, the header has already been permanently consumed from `src`. When the caller receives more network data and retries `Frame::decode`, the decoder attempts to parse the payload bytes as a new frame header, causing immediate unrecoverable stream desynchronization.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_04_frame_decode_header_destruction_on_truncation`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_04_frame_decode_header_destruction_on_truncation`
- **Remediation Patch**:
  Peek and decode the header without advancing `src` until the full frame payload is available:
  ```rust
  pub fn decode(src: &mut impl Buf, limits: FrameLimits) -> ProtocolResult<Self> {
      let mut cursor = std::io::Cursor::new(src.chunk());
      let header = FrameHeader::decode(&mut cursor, limits)?;
      let header_len = src.chunk().len() - cursor.remaining();
      let payload_len = usize::try_from(header.length).map_err(|_| ProtocolError::InvalidVarint)?;
      if src.remaining() < header_len + payload_len {
          return Err(ProtocolError::Truncated);
      }
      src.advance(header_len);
      let payload = src.copy_to_bytes(payload_len);
      Ok(Self { header, payload })
  }
  ```

---

### FINDING-05: `uk-server` Carrier Disconnect Drain Closes Shutdown Before Half-Closing Target Flows
- **Severity**: **High** (CVSS: 7.4 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
- **Affected Crate & File**: `crates/uk-server/src/relay/session.rs:280-285`
- **Root Cause & Trigger Chain**:
  In `close_session`, line 281 calls `shutdown.close()`, and line 282 calls `close_target_flows(target_writers)`. In `relay_client_to_target`, the worker task wakes up immediately on `shutdown.closed()`. At that moment, `close_target_flows` has not yet called `target.close_client_to_target()`. The task evaluates `flow_control.is_closed()`, finds it `false`, and immediately terminates without calling `target_writer.shutdown().await`. In-flight client data buffered in the relay is dropped, corrupting data in flight and violating `AGENTS.md` §3.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/src/relay/tests.rs::test_poc_finding_05_session_drain_order_inversion`
  - Command: `cargo test -p uk-server relay::tests::test_poc_finding_05_session_drain_order_inversion`
- **Remediation Patch**:
  In `crates/uk-server/src/relay/session.rs:280-285`, half-close target flows *before* firing the shutdown notification:
  ```rust
  transition(state, ServerSessionState::Closing);
  close_target_flows(target_writers);
  shutdown.close();
  drain_session_tasks(session_tasks, task_shutdown_timeout).await;
  ```

---

### FINDING-06: `uk-server` Opportunistic Prune Destroys Escalating Ban History
- **Severity**: **High** (CVSS: 7.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Affected Crate & File**: `crates/uk-server/src/rate_limit.rs:312-320`
- **Root Cause & Trigger Chain**:
  `AuthRateLimiter::prune` evaluates `now < banned_until` for banned entries. Once a ban expires (`now >= banned_until`), the record is immediately purged during the next opportunistic prune. The record is not retained for the duration of the quiet window (`window_secs`). When an attacker resumes brute-forcing after ban expiry, their record is missing, resetting `ban_count` to 0 and dropping the ban duration back to base `ban_secs` instead of escalating to $\text{ban\_secs} \times 2^n$.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/src/rate_limit.rs::test_poc_finding_06_opportunistic_prune_erases_escalating_ban_history`
  - Command: `cargo test -p uk-server rate_limit::tests::test_poc_finding_06_opportunistic_prune_erases_escalating_ban_history`
- **Remediation Patch**:
  Retain expired bans until a full quiet window (`window_secs`) has elapsed:
  ```rust
  let window = Duration::from_secs(self.config.window_secs);
  state.entries.retain(|_, rec| {
      if let Some(banned_until) = rec.banned_until {
          now < banned_until || now.saturating_duration_since(banned_until) < window
      } else {
          now.checked_duration_since(rec.window_start).is_some_and(|d| d < window)
      }
  });
  ```

---

### FINDING-07: `uk-server` Table Saturation Eviction Ignores Expired Bans
- **Severity**: **High** (CVSS: 7.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Affected Crate & File**: `crates/uk-server/src/rate_limit.rs:325-343`
- **Root Cause & Trigger Chain**:
  When `entries.len() >= MAX_ENTRIES` (65,536), eviction victim selection filters strictly on `if rec.banned_until.is_none()`. Any entry with an expired ban (`rec.banned_until = Some(expired_timestamp)`) is ignored. If opportunistic prune has not run, the table remains filled with expired bans. Line 340 sees `len() >= MAX_ENTRIES`, aborts tracking, and returns `false`. New attacking IPs bypass rate limiting entirely.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/src/rate_limit.rs::test_poc_finding_07_saturation_eviction_ignores_expired_bans`
  - Command: `cargo test -p uk-server rate_limit::tests::test_poc_finding_07_saturation_eviction_ignores_expired_bans`
- **Remediation Patch**:
  Include expired bans in the eviction victim selection:
  ```rust
  let mut victims = Vec::with_capacity(EVICTION_BATCH_SIZE);
  for (&entry_key, rec) in &state.entries {
      let is_active_ban = rec.banned_until.is_some_and(|until| now < until);
      if !is_active_ban {
          victims.push(entry_key);
          if victims.len() >= EVICTION_BATCH_SIZE {
              break;
          }
      }
  }
  for victim in victims {
      state.entries.remove(&victim);
  }
  ```

---

### FINDING-08: `uk-server` Two-Phase Replay Commit Race in `CommitGate` Bypasses `AuthRateLimiter`
- **Severity**: **High** (CVSS: 7.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Affected Crate & File**: `crates/uk-server/src/masking.rs:350-357`, `crates/uk-server/src/lib.rs:1193-1205, 1394-1398`
- **Root Cause & Trigger Chain**:
  When concurrent connections present identical `(identity, counter)` tuples, both pass Phase 1 precheck. The second connection to write ServerHello encounters `!(this.commit)(identity, counter)` in `CommitGate::poll_write`, failing with `"masking prelude replayed at commit"`. In `complete_handshake`, this error is mapped to `phase_error("tls accept", HandshakeFailureReason::Tls, err)`. In `serve_authenticated_carrier`, rate limit accounting triggers only for `HandshakeFailureReason::Auth | HandshakeFailureReason::Replay`. The replay collision is falsely categorized as TLS, evading `AuthRateLimiter`.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/src/masking.rs::test_poc_finding_08_commit_gate_replay_collision_classified_as_tls`
  - Command: `cargo test -p uk-server masking::tests::test_poc_finding_08_commit_gate_replay_collision_classified_as_tls`
- **Remediation Patch**:
  In `crates/uk-server/src/lib.rs:1394-1398`, inspect the error message and map replay collisions to `HandshakeFailureReason::Replay`:
  ```rust
  .map_err(|err| {
      let reason = if err.to_string().contains("replayed at commit") {
          HandshakeFailureReason::Replay
      } else {
          HandshakeFailureReason::Tls
      };
      phase_error("tls accept", reason, err)
  })?;
  ```

---

### FINDING-09: `uk-server` Masking Phase 1 Replay Rejection Merged Into "auth" Metric
- **Severity**: **Medium** (CVSS: 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`)
- **Affected Crate & File**: `crates/uk-server/src/masking.rs:223-230`
- **Root Cause & Trigger Chain**:
  In `MaskingState::reject`, line 228 unconditionally records `rejection.metrics.record_failed_handshake(HandshakeFailureReason::Auth);`, even when `kind == RejectKind::Replay`. This merges replay failures into the auth metric, directly violating the `AGENTS.md` §2 invariant.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/src/masking.rs::test_poc_finding_09_masking_phase1_replay_merged_into_auth_metric`
  - Command: `cargo test -p uk-server masking::tests::test_poc_finding_09_masking_phase1_replay_merged_into_auth_metric`
- **Remediation Patch**:
  In `crates/uk-server/src/masking.rs:223-230`:
  ```rust
  let failure_reason = match kind {
      RejectKind::Prelude => {
          rejection.metrics.record_mask_prelude_reject();
          HandshakeFailureReason::Auth
      }
      RejectKind::Replay => {
          rejection.metrics.record_mask_replay_reject();
          HandshakeFailureReason::Replay
      }
  };
  rejection.metrics.record_failed_handshake(failure_reason);
  ```

---

### FINDING-10: `uk-server::silent_drain` Early Return on EOF / Read Limit Bypasses Dwell Timing Posture
- **Severity**: **Medium** (CVSS: 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **Affected Crate & File**: `crates/uk-server/src/masking.rs:260-288`
- **Root Cause & Trigger Chain**:
  In `silent_drain`, line 277 matches `Ok(0) | Err(_) => return`. When a client sends an invalid prelude and immediately issues `shutdown(Write)` (FIN), the server sees `Ok(0)` and returns in milliseconds. `tcp` is dropped with `SO_LINGER=0`, emitting a TCP RST and leaking a timing oracle that bypasses the uniform rejection dwell ($[1/2, 1] \times \text{admission\_timeout}$) required by `AGENTS.md` §3.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/src/masking.rs::test_poc_finding_10_silent_drain_early_return_on_eof`
  - Command: `cargo test -p uk-server masking::tests::test_poc_finding_10_silent_drain_early_return_on_eof`
- **Remediation Patch**:
  In `silent_drain`, when seeing `Ok(0)`, disable read polling and sleep until `deadline`:
  ```rust
  let mut read_done = false;
  loop {
      if *shutdown_rx.borrow() { return; }
      tokio::select! {
          _ = shutdown_rx.changed() => return,
          read = tcp.read(&mut sink), if !read_done => match read {
              Ok(0) | Err(_) => { read_done = true; }
              Ok(_) => {
                  reads += 1;
                  if reads >= DRAIN_MAX_READS { read_done = true; }
              }
          },
          () = time::sleep_until(deadline) => return,
      }
  }
  ```

---

### FINDING-11: `uk-policy::Cidr::contains` IPv6 `::/0` Matches IPv4-Mapped Addresses
- **Severity**: **Medium** (CVSS: 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`)
- **Affected Crate & File**: `crates/uk-policy/src/lib.rs:385-390, 334-338`
- **Root Cause & Trigger Chain**:
  `Cidr::contains` matches `(Self::V6(network, prefix), IpAddr::V6(ip))` by applying `ipv6_mask(*prefix)`. For `::/0`, the mask is 0, which matches all IPv6 addresses, including IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`). This contradicts the specification at line 334 ("an IPv6 CIDR never matches a plain IPv4 address... `cidr = '::/0'` does not cover IPv4").
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_11_ipv6_cidr_matches_ipv4_mapped_address`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_11_ipv6_cidr_matches_ipv4_mapped_address`
- **Remediation Patch**:
  Canonicalize IPv4-mapped IPv6 addresses before evaluating CIDR containment:
  ```rust
  pub fn contains(&self, ip: IpAddr) -> bool {
      let ip = match ip {
          IpAddr::V6(v6) => {
              if let Some(v4) = ipv4_mapped(v6) {
                  IpAddr::V4(v4)
              } else {
                  IpAddr::V6(v6)
              }
          }
          IpAddr::V4(v4) => IpAddr::V4(v4),
      };
      match (self, ip) {
          (Self::V4(network, prefix), IpAddr::V4(ip)) => {
              let mask = ipv4_mask(*prefix);
              u32::from(*network) & mask == u32::from(ip) & mask
          }
          (Self::V6(network, prefix), IpAddr::V6(ip)) => {
              let mask = ipv6_mask(*prefix);
              u128::from(*network) & mask == u128::from(ip) & mask
          }
          _ => false,
      }
  }
  ```

---

### FINDING-12: `uk-auth::ReplayCache` Capacity Eviction Allows Replay Attacks Under Handshake Flooding
- **Severity**: **Medium** (CVSS: 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`)
- **Affected Crate & File**: `crates/uk-auth/src/lib.rs:507-514`
- **Root Cause & Trigger Chain**:
  In `check_and_insert_at`, when `entries.len() >= max_entries`, `evict_oldest()` unconditionally removes the oldest entry even if its timestamp has not exceeded `window`. An authenticated client flooding 65,536 handshakes purges legitimate active nonces, permitting replays of previously accepted challenge-response pairs within the time window.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_12_replay_cache_capacity_eviction_permits_replay`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_12_replay_cache_capacity_eviction_permits_replay`
- **Remediation Patch**:
  Under saturation, fail closed rather than evicting unexpired active nonces:
  ```rust
  self.prune(inserted_at);
  if self.entries.len() >= self.max_entries {
      return Err(AuthError::ResourceLimit("replay cache saturated"));
  }
  ```

---

### FINDING-13: `uk-server` Global Failure Governor Integer Floor Division Breaks Bounded Memory
- **Severity**: **Medium** (CVSS: 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-server/src/rate_limit.rs:138-141`
- **Root Cause & Trigger Chain**:
  `bucket_width` is computed as `Duration::from_secs((config.window_secs / GLOBAL_BUCKET_COUNT as u64).max(1))`. For `window_secs = 120`, $120 / 64 = 1\text{s}$. Sliding window entries are retained for 120 seconds, accumulating up to 120 buckets. This violates the `AGENTS.md` §2 invariant: "Memory must stay bounded ($\le \text{GLOBAL\_BUCKET\_COUNT} + 1$ time buckets) regardless of window size."
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/src/rate_limit.rs::test_poc_finding_13_global_governor_integer_floor_division`
  - Command: `cargo test -p uk-server rate_limit::tests::test_poc_finding_13_global_governor_integer_floor_division`
- **Remediation Patch**:
  Use ceiling division to ensure $\lceil \text{window\_secs} / \text{bucket\_width} \rceil \le \text{GLOBAL\_BUCKET\_COUNT}$:
  ```rust
  let bucket_width = Duration::from_secs(
      ((config.window_secs + GLOBAL_BUCKET_COUNT as u64 - 1) / GLOBAL_BUCKET_COUNT as u64).max(1),
  );
  ```

---

### FINDING-14: `uk-server` Target Dial Rejection Error Propagation via `?` Leaks Flow Slots
- **Severity**: **Medium** (CVSS: 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-server/src/relay/tcp.rs:587-591`, `udp.rs:396-400`
- **Root Cause & Trigger Chain**:
  Upon target dial failure, `reject_open_failure` attempts to send an error frame over the carrier. If the carrier connection has closed or is congested, `reject_open_failure(...).await?` returns early. The subsequent `remove_flow_slot(target_writers, flow_id)` is bypassed, stranding `FlowSlot::OpeningTcp`/`OpeningUdp` in the flow table and violating flow table hygiene.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/src/relay/tests.rs::test_poc_finding_14_target_open_failure_flow_slot_leak`
  - Command: `cargo test -p uk-server relay::tests::test_poc_finding_14_target_open_failure_flow_slot_leak`
- **Remediation Patch**:
  Remove the flow slot unconditionally before awaiting notification:
  ```rust
  Err(err) => {
      remove_flow_slot(target_writers, flow_id);
      let _ = reject_open_failure(flow_id, &target, err, context).await;
  }
  ```

---

### FINDING-15: `uk-server` SIGHUP Limits Validation Omits `auth_rate_limit_global_failures`
- **Severity**: **Medium** (CVSS: 4.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`)
- **Affected Crate & File**: `crates/uk-server/src/lib.rs:905-986`
- **Root Cause & Trigger Chain**:
  `reload_static_limits` checks 27 static configuration limits to ensure hot-reload does not modify immutable parameters. It checks `auth_rate_limit_failures`, `auth_rate_limit_window_seconds`, and `auth_rate_limit_ban_seconds`, but omits `auth_rate_limit_global_failures`. Modifying this value in `server.toml` during SIGHUP passes validation without updating the running governor, causing silent configuration divergence.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_15_sighup_limits_omits_global_failures_threshold`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_15_sighup_limits_omits_global_failures_threshold`
- **Remediation Patch**:
  Add `auth_rate_limit_global_failures` to `reload_static_limits` (increasing count to 28):
  ```rust
  (
      "auth_rate_limit_global_failures",
      config.auth_rate_limit_config().global_failure_threshold as u64,
  ),
  ```

---

### FINDING-16: `uk-client` Unbounded `connection.accept_bi()` Hang in Client QUIC Connect
- **Severity**: **Medium** (CVSS: 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-client/src/quic.rs:285`
- **Root Cause & Trigger Chain**:
  In `connect_quic`, client connection establishment wraps the TLS handshake in a deadline, but once connected, line 285 calls `connection.accept_bi().await` with no timeout. If a misbehaving or stalled server maintains keepalives but never opens the bidirectional control stream, the client task hangs indefinitely, starving connection pool resources.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-client/tests/poc_quic_client_hang.rs::test_poc_finding_16_client_quic_accept_bi_unbounded_hang`
  - Command: `cargo test -p uk-client --test poc_quic_client_hang`
- **Remediation Patch**:
  Wrap `accept_bi` in a timeout matching the handshake timeout:
  ```rust
  let (send, recv) = match tokio::time::timeout(deadline, connection.accept_bi()).await {
      Ok(Ok(bi)) => bi,
      Ok(Err(err)) => { /* close and return error */ }
      Err(_) => { /* close and return timeout error */ }
  };
  ```

---

### FINDING-17: `uk-proto::FrameHeader::decode` Wire Length Underrun Consumes Buffer on Truncation
- **Severity**: **Medium** (CVSS: 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-proto/src/frame.rs:166-180`
- **Root Cause & Trigger Chain**:
  Line 166 checks `if src.remaining() < 4 { return Err(ProtocolError::Truncated); }`. The minimal wire length of a complete `FrameHeader` is 6 bytes (1 version + 1 type + 2 flags + 1 id + 1 length). For inputs of 4 or 5 bytes, the first 4 bytes are consumed before `varint::decode` returns `Truncated`, corrupting the caller's buffer.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_17_frame_header_decode_consumes_bytes_on_4_byte_input`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_17_frame_header_decode_consumes_bytes_on_4_byte_input`
- **Remediation Patch**:
  Update minimum bound check to 6 bytes:
  ```rust
  if src.remaining() < 6 {
      return Err(ProtocolError::Truncated);
  }
  ```

---

### FINDING-18: `uk-proto::read_frame` Blocks on Socket for 3 More Bytes When Version Is Invalid
- **Severity**: **Medium** (CVSS: 4.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-proto/src/io.rs:56-66`
- **Root Cause & Trigger Chain**:
  `first` is read via `read_optional_one(reader)`. Line 61 immediately issues `read_exact_or_truncated(reader, &mut fixed[1..]).await?` *before* validating `first == VERSION`. If a client sends an invalid version byte (e.g. 0x09) and closes the socket, `read_frame` returns `ProtocolError::Truncated` instead of `UnsupportedVersion(9)`.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_18_read_frame_blocks_on_invalid_version`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_18_read_frame_blocks_on_invalid_version`
- **Remediation Patch**:
  Validate `first == VERSION` immediately after reading the first byte:
  ```rust
  let Some(first) = read_optional_one(reader).await? else {
      return Err(FrameIoError::Closed);
  };
  if first != VERSION {
      return Err(ProtocolError::UnsupportedVersion(first).into());
  }
  fixed[0] = first;
  read_exact_or_truncated(reader, &mut fixed[1..]).await?;
  ```

---

### FINDING-19: `uk-proto::Settings::decode` Unbounded Loop & Missing Wire Length Check
- **Severity**: **Medium** (CVSS: 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-proto/src/settings.rs:134-152`
- **Root Cause & Trigger Chain**:
  `Settings::decode` decodes `count` and executes `for _ in 0..count` without validating `src.remaining() >= count * 2`. A malformed frame declaring `count = 100_000` with limited bytes forces iterative varint decoding before failing.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_19_settings_decode_unbounded_loop`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_19_settings_decode_unbounded_loop`
- **Remediation Patch**:
  Cap `count` and validate buffer length upfront:
  ```rust
  const MAX_SETTINGS_COUNT: usize = 64;
  if count > MAX_SETTINGS_COUNT {
      return Err(ProtocolError::InvalidSettings("too many settings entries"));
  }
  if src.remaining() < count.saturating_mul(2) {
      return Err(ProtocolError::Truncated);
  }
  ```

---

### FINDING-20: `uk-auth::AuthResponse::decode` Allocates Capabilities Vec on Truncated HMAC Tag
- **Severity**: **Medium** (CVSS: 4.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-auth/src/lib.rs:406-439`
- **Root Cause & Trigger Chain**:
  `read_varbytes` parses capabilities and allocates a `Vec<u8>`. Only after this allocation does line 424 check `src.remaining() < 32` for the HMAC tag. If the tag is truncated, heap allocation was performed prematurely, violating the pre-allocation bounds check invariant in `AGENTS.md` §1.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_20_auth_response_allocates_capabilities_on_truncated_tag`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_20_auth_response_allocates_capabilities_on_truncated_tag`
- **Remediation Patch**:
  Verify mandatory 32-byte tag presence before allocating capabilities:
  ```rust
  let cap_len = usize::try_from(varint::decode(src)?).map_err(|_| ProtocolError::InvalidVarint)?;
  if src.remaining() < cap_len.saturating_add(32) {
      return Err(AuthError::InvalidPayload("response tag is truncated"));
  }
  ```

---

### FINDING-21: `uk-auth::AuthChallenge::decode` Partial Buffer Consumption on 40..41 Byte Inputs
- **Severity**: **Low** (CVSS: 3.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-auth/src/lib.rs:274-292`
- **Root Cause & Trigger Chain**:
  Minimum wire length of `AuthChallenge` is 42 bytes (32 nonce + 8 time + 1 caps + 1 limits). Line 275 checks `src.remaining() < 40`. On 40 or 41 bytes, 40 bytes are consumed before returning `ProtocolError::Truncated` instead of `InvalidPayload("challenge is truncated")`.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_21_auth_challenge_decode_inconsistent_error_on_40_bytes`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_21_auth_challenge_decode_inconsistent_error_on_40_bytes`
- **Remediation Patch**:
  Check `src.remaining() < 42` at entry.

---

### FINDING-22: `uk-proto::TcpOpen::decode` Consumes Target Before Validating `open_flags` Presence
- **Severity**: **Low** (CVSS: 3.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Affected Crate & File**: `crates/uk-proto/src/tcp.rs:43-55`
- **Root Cause & Trigger Chain**:
  `TcpOpen::decode` consumes `Target` (8+ bytes) before checking `src.remaining() < 2` for `open_flags`. On truncated inputs, the target bytes are consumed from the caller's buffer before failing with `Truncated`.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_22_tcp_open_decode_consumes_target_on_truncated_flags`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_22_tcp_open_decode_consumes_target_on_truncated_flags`
- **Remediation Patch**:
  Check `src.remaining() < 10` before decoding target.

---

### FINDING-23: `uk-policy` Restricted Address Classifier Omits RFC 7343 ORCHIDv2 (`2001:20::/28`)
- **Severity**: **Low** (CVSS: 3.7 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`)
- **Affected Crate & File**: `crates/uk-policy/src/lib.rs:718-721`
- **Root Cause & Trigger Chain**:
  `is_ipv6_orchid` checks `(segments[1] & 0xfff0) == 0x0010` (RFC 4843 ORCHIDv1). RFC 7343 defined ORCHIDv2 (`2001:20::/28`) as non-routable special-purpose IPv6 space. Because `0x0020` is not checked, ORCHIDv2 addresses are evaluated as non-private and permitted under default allow policies.
- **PoC Test Reference & Reproduction**:
  - Test: `crates/uk-server/tests/adversarial_poc_audit.rs::test_poc_finding_23_orchid_v2_not_classified_as_restricted`
  - Command: `cargo test --test adversarial_poc_audit test_poc_finding_23_orchid_v2_not_classified_as_restricted`
- **Remediation Patch**:
  In `crates/uk-policy/src/lib.rs:720`, check both `0x0010` and `0x0020`:
  ```rust
  fn is_ipv6_orchid(ip: Ipv6Addr) -> bool {
      let segments = ip.segments();
      segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020)
  }
  ```

---

## 4. Production Readiness Conclusion

The Uncrowned King codebase demonstrates rigorous cryptographic hygiene (`unsafe_code = "forbid"`, constant-time HMAC verification with dummy calculations on missing credentials, strict RFC 9000 canonical varints, and permanent cloud provider IMDS exclusion).

However, the 23 discrete findings identified in this audit expose concrete denial-of-service, rate limiting evasion, and protocol desynchronization vectors that must be hardened prior to enterprise production deployment. Implementing the provided remediation patches resolves all identified invariant departures.
