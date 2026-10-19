# Uncrowned King Threat Model

This document states what Uncrowned King (UK) defends against, how, and what it
does not. It is grounded in the whitepaper §16 security requirements and the
current implementation. It is a living document; revise it when the protocol or
implementation changes.

## 1. System overview

```
SOCKS5 app ──(loopback)──▶ uk-client ══(TLS/TCP or QUIC, uk/1)══▶ uk-server ──▶ target
```

- **uk-client** exposes a local SOCKS5 CONNECT / UDP ASSOCIATE endpoint and
  relays flows to the server over an authenticated, encrypted carrier.
- **uk-server** authenticates carriers, enforces policy, and relays to targets.
- The carrier is TLS 1.3 over TCP or QUIC; both negotiate ALPN `uk/1`.

## 2. Assets

| Asset | Where | Protection goal |
| --- | --- | --- |
| Shared secret (per key id) | client config, server config | confidentiality, integrity |
| Server TLS/QUIC private key | server host | confidentiality |
| Relayed payload data | in transit | confidentiality, integrity |
| Policy definition | server host | integrity |
| Server availability | server process | availability under bounded resources |

## 3. Trust boundaries

- **Trusted**: the server host and its private key; the shared secret held by
  legitimate clients; the policy file; loaded configuration.
- **Semi-trusted**: the local SOCKS5 application (same host as the client; the
  loopback endpoint has no user authentication — see §6).
- **Untrusted**: the network between client and server; the relay target and
  everything it returns; any peer that has not completed authentication.

## 4. Adversaries and mitigations

### 4.1 Network attacker (passive or active MITM)

*Goal: read/modify relayed data, impersonate server, hijack a session.*

- **TLS 1.3 / QUIC only**, no plaintext UK, no earlier TLS versions
  (`tls::server_config` / client config pin `TLS13`). Confidentiality and
  integrity of all UK frames rest on the transport.
- **ALPN `uk/1` is verified** on both carriers before any UK frame is processed
  (`verify_alpn`); a mismatch fails the connection.
- **No 0-RTT application data**: TLS `max_early_data_size = 0`; the QUIC control
  stream is opened only after the 1-RTT handshake. UK data is never processed
  through early data.
- **Authentication is bound to the transport** via the TLS/QUIC keying-material
  exporter (`EXPORTER_LABEL`). A relayed or MITM'd handshake cannot be replayed
  onto a different transport session, preventing channel-splicing.
- Server identity is validated by the client against its configured CA;
  certificate rotation is atomic (see [`key-management.md`](key-management.md)).

### 4.2 Unauthenticated peer / credential guesser

*Goal: open a session without the shared secret.*

- **HMAC challenge-response** (`uk-auth`): the server issues a random challenge;
  the client proves knowledge of the shared secret over the exporter-bound
  transcript. Verification uses **constant-time comparison**.
- **Timestamp skew bound** (`auth_skew_seconds`, default 30) rejects stale
  authentication attempts.
- **Bounded pre-auth input**: `max_pre_auth_bytes` (≥ minimum `AUTH_RESPONSE`)
  and `max_handshakes` cap resource use before a peer is authenticated.

### 4.3 Replay attacker

*Goal: replay a captured authentication to open a new session.*

- **Replay cache** of recent nonce material within a bounded window
  (`replay_cache_window_seconds`, `replay_cache_max_entries`), combined with the
  timestamp-skew bound, rejects replayed `AUTH_RESPONSE` messages.

### 4.4 Malicious target or SSRF via relayed request

*Goal: make the server reach internal/metadata endpoints.*

- **Deny-all by default**: with no `policy_path`, every target is denied.
- **Private/reserved ranges denied**: `private = true` matches private,
  loopback, link-local, documentation, multicast, unspecified, shared,
  benchmarking, and reserved ranges — **including resolved domain addresses**.
- **Cloud metadata endpoints are hard-denied** before ordered rules run
  (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`).
- **Policy is checked after DNS resolution and before dialing**, so a domain
  that resolves into a denied range is rejected (no TOCTOU on the resolved
  address).

### 4.5 Resource-exhaustion / denial of service

*Goal: exhaust server memory, sockets, or tasks.*

- Bounded, configurable limits both **before and after** authentication:
  `max_sessions`, `max_handshakes`, `max_streams`, `max_udp_flows`,
  `max_outbound_dials_per_session`, `max_buffered_bytes_per_session`,
  `max_buffered_bytes_per_flow`, `max_frame_size`, plus idle/handshake/connect/
  half-close/UDP-idle timeouts and a bounded shutdown drain.
- **Strict frame and target parsing** with explicit length checks; the parsers
  are fuzzed (whitepaper §20) and must never panic on arbitrary bytes.
- Listener accept errors use **capped exponential backoff** rather than a hot
  loop.

### 4.6 Local unprivileged user on client or server host

*Goal: read the shared secret or private key from disk.*

- **File-permission checks**: secret- and key-bearing files must not be
  group/other readable, writable, or executable on Unix
  (`validate_sensitive_file_permissions`).
- **Secrets are zeroized** on drop and kept out of relay session state; they are
  never written to logs.

### 4.7 Log-injection / information disclosure via logs

- Structured JSON logging with **escaped fields**; targets are rendered
  log-safe (`log_safe`). Secrets and key material are never logged. The
  observability endpoint exposes only aggregate counters, no payloads.

## 5. Security invariants (must always hold)

1. No UK frame is processed before the transport handshake completes and ALPN
   is verified.
2. No DNS lookup, outbound dial, or policy decision happens before
   `AUTHENTICATED`.
3. Authentication is bound to the specific transport session (exporter).
4. The first policy rule to match wins; metadata/private denials precede any
   allow.
5. Every configured limit is enforced; parsing untrusted bytes never panics.
6. `unsafe_code` is forbidden workspace-wide.

## 6. Residual risks and non-goals

- **Traffic analysis / fingerprinting**: UK does not hide that a TLS/QUIC
  connection exists or obfuscate timing and volume beyond what the transport
  provides. It is not a pluggable-transport obfuscation layer.
- **Shared-secret compromise**: a leaked secret allows full client
  impersonation until the credential is rotated/revoked (see
  [`key-management.md`](key-management.md)). There is no per-message forward
  secrecy for the *auth secret*; the transport provides forward secrecy for
  *data*.
- **Local SOCKS endpoint has no user authentication.** The client rejects
  non-loopback SOCKS listen addresses unless `--allow-non-loopback` is set;
  operators using that override must supply their own network access control.
- **Observability endpoint is unauthenticated.** Bind it to loopback or a
  protected management network.
- **Transport-layer DoS / amplification** (e.g., QUIC handshake floods) relies
  on the correctness of the underlying `rustls`/`quinn` stacks; UK adds
  application-layer limits on top.
- **Compromised server host** is out of scope: it holds the private key and
  sees plaintext relayed data by design.

## 7. Verification

- Protocol test plan (valid/invalid auth, replay, expired timestamp, oversized/
  truncated frames, policy denial, resource limits, carrier fallback, log
  escaping): whitepaper §20, exercised by the workspace test suite.
- Fuzzing of all strict parsers: `crates/uk-proto/fuzz` (nightly + cargo-fuzz),
  run in CI by `.github/workflows/fuzz.yml`.
- Supply chain: RustSec advisory audit and `cargo-deny` (licenses/sources/bans)
  in `.github/workflows/security.yml`.
