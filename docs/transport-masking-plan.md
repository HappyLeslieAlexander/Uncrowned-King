# Transport Masking — Iteration Plan

> Status: Phases 0–3 implemented (2026-10-25); see CHANGELOG Unreleased
> Baseline: `v1.0.2` + HEAD (2026-10-25)
> Inspiration: the `morph` transport-masking layer of
> [Nowhere](https://github.com/NodePassProject/Nowhere) (NodePassProject, GPL-3.0).
> This is a clean-room design: we reuse the *constructions*, not their code.

## 1. Problem statement

UK's carriers are standard TLS 1.3 (`uk/1` ALPN) over TCP, and QUIC. Both are
trivially identifiable by passive observers today:

- **TLS/TCP**: the ClientHello is plaintext. SNI and the non-standard ALPN
  `uk/1` (`crates/uk-proto/src/lib.rs:4`) are visible on every connection.
- **QUIC**: client Initial packets are encrypted with keys publicly derivable
  from the DCID (RFC 9001 §5.2), so a passive observer can decrypt them and
  read the same ClientHello (SNI, ALPN).

Active probing is also cheap: an unauthenticated prober completes a full TLS
handshake (burning a server certificate signature per connection) before the
HMAC challenge rejects it. The current defenses — per-IP auth-failure banning
(`crates/uk-server/src/rate_limit.rs:12-57`), handshake permits, QUIC stateless
retry — limit cost, not detectability.

`docs/threat-model.md` currently lists traffic-analysis/fingerprinting hiding
as a **non-goal** ("It is not a pluggable-transport obfuscation layer",
lines 136–138). This plan moves a narrow slice of that non-goal into scope as
an **opt-in** capability, without weakening any existing invariant.

## 2. Goals

1. **G1 — Passive fingerprint removal (opt-in).** When enabled, an observer
   with no credential cannot distinguish a UK listener from random bytes: no
   visible ClientHello, SNI, ALPN, certificate, or QUIC long-header structure.
2. **G2 — Cheap admission before expensive crypto.** Prelude verification
   (a few HMAC-SHA256 ops) gates the rustls handshake, so blind probes never
   reach certificate signing.
3. **G3 — Silent rejection semantics.** All pre-authentication failures
   (bad tag, replay, malformed hello, timeout) produce no distinguishable
   response: bounded drain, absolute deadline, abortive close.
4. **G4 — Zero changes to the security core.** TLS exporter channel binding,
   ALPN verification, 0-RTT-disabled policy, the AUTH challenge/response flow,
   and `uk-policy` evaluation are untouched. Masking sits *below* TLS/QUIC.

## 3. Non-goals

- No traffic-analysis resistance (timing, volume, flow-count fingerprints).
- No browser-fingerprint mimicry (uTLS-style ClientHello shaping). Rejected:
  requires replacing rustls ClientHello generation; see §13.
- No wire compatibility with Nowhere/morph. Our auth model (multi-credential
  `key_id` + secret) differs from theirs (single shared key); labels and
  layout diverge deliberately.
- No protection against a credential holder burning its own replay window,
  and no forward secrecy for prelude metadata. Both are documented limits of
  the construction (inherited, see §11).

## 4. Key design decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Feature name: **transport masking** (`[masking]` config). Do not call it "morph". | Avoid implying Nowhere wire compat; matches existing config vocabulary. |
| D2 | **Default off** on both sides. | README positions UK on standard transports; masking is a deployment posture choice. Secure-by-default = standard, auditable TLS/QUIC. |
| D3 | Mask layer sits **below** TLS/QUIC as an `AsyncRead`/`AsyncWrite` wrapper (TCP) and an `AsyncUdpSocket` wrapper (QUIC). | G4: exporter binding and ALPN checks live inside the TLS session and are blind to an outer XOR layer. |
| D4 | Keys derived **per credential**: `root = HMAC-SHA256(secret, "uk/1/mask/root" ‖ key_id)`, then domain-split into `tcp-auth`, `tcp-mask`, `udp-c2s`, `udp-s2c` keys. | Inherits UK's multi-credential model and revocation; no single master key. |
| D5 | No `key_id` on the wire pre-TLS. The server verifies the prelude tag against **every** configured credential in a padded, constant-cost loop (mirror of `find_credential` / dummy-HMAC in `crates/uk-auth/src/lib.rs:746-787`). | Keeping credential identity masked preserves G1; per-probe cost stays microseconds for realistic credential counts. Document an operational cap (e.g. ≤ 64 credentials when masking is on). |
| D6 | Replay: per-client-process random 64-bit **identity** + monotonic 48-bit **counter**, 1024-bit sliding window per identity, fixed 16 384-identity FIFO registry (~2.5 MiB preallocated). **Two-phase commit**: tag precheck → ClientHello parsed by rustls → atomic commit before any TLS response bytes. | Proven construction (Nowhere); only key holders can reach the commit point; malformed hellos do not burn counters. |
| D7 | Cipher: ChaCha20 keystream (RustCrypto `chacha20` crate, `zeroize` feature) — masking only, **not** an integrity layer. TLS/QUIC remain the sole AEAD. | Pure Rust (workspace `unsafe_code = "forbid"`), MIT/Apache-2.0 (GPL-compatible; add to `deny.toml` audit), fast, keystream seeks for partial-write rollback. |
| D8 | Prelude shaping policy `fade` (default) / `full8` / `low7` for the first 64 bytes. | Cheap middlebox-tolerance knob; construction documented in Nowhere's `docs/prelude.md`. |
| D9 | Mask prelude failures feed the existing `auth_rate_limit_*` limiter (count as auth failures). | Reuses ban machinery; blind probing degrades exactly like password guessing does today. |
| D10 | New workspace crate `crates/uk-mask` holding codec + wrappers + replay registry. | Keeps `uk-proto` dependency-free of `chacha20`; isolates test surface. |

## 5. Phase 0 — Design freeze (RFC)

**Effort: 2–3 dev-days. No runtime code.**

- [ ] Review/accept this plan (decision points D1–D10 sign-off).
- [ ] Wire-format spec for the UK Prelude (64 B prelude layout, 7-bit tail
      encoding of `identity ‖ counter ‖ tag(14 B)`, 12 B nonce) as a new
      section in `docs/spec-v1.0.md` or a `docs/masking-spec.md`.
- [ ] Key-schedule test vectors added to `docs/test-vectors.md` (root/auth/mask
      derivation, tag computation, 7-bit encode/decode edges).
- [ ] Amend `docs/threat-model.md`: narrow the traffic-fingerprinting non-goal
      to "not provided by default; opt-in transport masking (§ref) removes
      passive protocol identification only", plus the new documented limits.
- [ ] Decide endpoint syntax: keep `tls://`/`quic://` schemes and a global
      `[masking].enabled` (recommended), vs. new `masked+tls://` schemes for
      per-endpoint control in `server_addrs`.

**Acceptance:** spec + vectors merged; threat model updated; no behavior change.

## 6. Phase 1 — TCP carrier masking

### 1a. Core (effort: 8–10 dev-days)

Scope: masked `tls://` end-to-end (SOCKS TCP relay + UDP-over-stream), server
and client.

- **`crates/uk-mask`** (new):
  - prelude codec (encode/decode, policy shaping, constant-time tag compare
    via `subtle`);
  - `MaskedStream<S: AsyncRead + AsyncWrite>` — per-direction ChaCha20 with
    byte offsets, keystream rollback (`try_seek`) on partial writes;
  - replay registry (preallocated, no per-flow allocation, mutex released
    before any I/O);
  - key schedule per D4.
- **Server** (`crates/uk-server/src/lib.rs` accept path, `spawn_accepted`):
  read prelude+nonce before `TlsAcceptor`; verify against all credentials
  (D5); on failure → silent drain (bounded 4 KiB / 64 reads) until
  `handshake_timeout_seconds` deadline, then abortive close (`SO_LINGER=0`
  semantics), count into the auth limiter (D9); on success → wrap stream and
  hand to rustls. Handshake semaphore is taken **after** prelude passes.
- **Client** (`crates/uk-client/src/session.rs:349+`, TCP branch):
  allocate identity lazily per process; allocate counter immediately before
  encoding; write prelude+nonce; wrap stream before `TlsConnector::connect`.
  Carrier fallback (`quic://`→`tls://`) is unaffected; masking state is
  per-endpoint-attempt.
- **Config**: server `[masking] enabled`, `replay_identities`,
  `prelude_policy`; client `[masking] enabled`. Both default `false`; config
  whitelist (`scripts/helm-config-check.sh`) extended.
- **Metrics** (Prometheus text format, HELP/TYPE):
  `…_mask_prelude_rejects_total`, `…_mask_replay_rejects_total`,
  `…_mask_handshake_timeouts_total` (server); client failure counter only.
- **SIGHUP reload**: mask keys are captured per-connection at accept time;
  reload swaps credential state for *new* connections only — preserves the
  atomic-reload invariant.

**Acceptance (1a):**
- Full SOCKS5 TCP + UDP ASSOCIATE relay over masked TLS (interop test,
  both `examples/` configs with masking on).
- Unmasked client → masked server: client observes handshake timeout;
  server sends zero TLS bytes, metric increments.
- Masked client → unmasked server: TLS decode failure (documented
  misconfiguration signature; not a probe vector since it requires a key).
- Blind prober (random bytes, valid-looking prelude with bad tag): no
  response bytes before deadline; rustls never invoked (assert via metric
  counters / test hook).
- Property tests: codec round-trip under random chunking; keystream offset
  rollback across partial writes (`Pending`, 0-byte, `WouldBlock`).
- Replay tests: duplicate/zero/below-window rejection, window edges 0/1023/
  1024, eviction then re-registration, concurrent counter uniqueness.
- Timing test (SEC-08 pattern): prelude verification cost uniform across
  unknown/known `key_id` sets.

### 1b. Hardening (effort: 3–4 dev-days)

- **Silent two-phase acceptor**: drive `rustls::ServerConnection` manually
  (`read_tls`/`process_new_packets`/`write_tls`) so the replay counter is
  committed only after a *parseable* ClientHello and strictly before the
  first response byte flushes. Replaces the 1a single-phase commit.
- Prelude shaping policies shipped (`fade` default, `full8`, `low7`) with
  middlebox-oriented tests (7-bit-clean path).
- Fuzz-style property run (cargo-fuzz optional): prelude decoder and
  keystream wrapper against arbitrary byte/chunk sequences, bounded memory
  assertions.

**Acceptance (1b):** malformed ClientHello with a *valid* tag does not burn a
counter; response ordering asserted (commit precedes first write) in tests.

## 7. Phase 2 — QUIC carrier masking

**Effort: 6–8 dev-days. Depends on Phase 1.**

- `MaskedUdpSocket` implementing quinn's `AsyncUdpSocket` (wrap the sockets
  under `crates/uk-server/src/quic.rs:140-153` `bind_endpoint` and
  `crates/uk-client/src/quic.rs:105-150` `connect`):
  - per-segment wire format `nonce(12 B) ‖ ChaCha20(payload)`;
  - GSO send path (wire stride = segment + 12) and GRO receive path
    (per-slot scratch, `RecvMeta` len/stride rewrite);
  - `max_udp_payload_size` and MTU-discovery upper bound reduced by 12
    (1440), keeping the DATAGRAM-frame 16 KiB ceiling docs consistent
    (`docs/tuning.md` §1.1.1 cross-reference).
- **Server ingress filter** after unmask: long headers must carry a
  supported QUIC version or the segment is dropped silently — no Version
  Negotiation response to anyone without the mask key. Stateless retry
  (`incoming.retry()`) is untouched: it runs above the mask layer; Retry
  packets are masked on the way out like everything else.
- Keep-alive (15 s) / idle-timeout (60 s) and receive-window invariants
  (`quic_connection_receive_window ≥ quic_stream_receive_window`) unchanged —
  they live in quinn config above the socket.
- Config: `[masking] quic = true` (independent of TCP masking).
- Degraded-carrier cache interplay: masked-QUIC handshake timeout marks the
  endpoint degraded as today; no new states.

**Acceptance:** masked QUIC session carries SOCKS TCP + UDP (DATAGRAM frames
and stream fallback); unauthenticated UDP prober (random bytes, version-0,
unsupported version) receives zero responses of any kind; retry flow works
under mask; GRO multi-segment datagrams decode correctly (Linux CI), macOS
single-segment path covered locally; throughput overhead measured (§8).

## 8. Phase 3 — Operations, docs, release

**Effort: 4–5 dev-days.**

- Helm: `server.masking.*` / `client.masking.*` values (default off),
  rendered through the existing config-check pipeline; standalone manifest
  parity (`deploy/kubernetes/`) if knobs are exposed there.
- Docs: `docs/operations.md` (deploying with masking, credential-count cap,
  rotating a credential invalidates mask keys), `docs/tuning.md` (MTU
  interaction, replay registry sizing), README feature table entry,
  `docs/audits/` masking security-review note.
- Benchmarks (criterion): masked vs. unmasked TCP and QUIC throughput +
  handshake latency; record in `docs/performance.md`.
- CHANGELOG entry; version bump + GPG-signed release via the
  `publish-release` runbook (atomic manifest sync per AGENTS.md §4).
- Attribution note in CHANGELOG/docs: construction inspired by Nowhere's
  morph layer (GPL-3.0, NodePassProject); no source derived.

## 9. Cross-phase engineering requirements (AGENTS.md mapping)

- `unsafe_code = "forbid"` holds in `uk-mask` (D7 dependency choice).
- Constant-time: tag compare via `subtle::ConstantTimeEq`; unknown-credential
  path performs a full dummy HMAC — same discipline as `uk-auth`.
- Bounded memory: prelude read is a fixed 76 bytes; replay registry is
  preallocated (~2.5 MiB at 16 384 identities); no per-flow heap allocation
  in admission; drain buffer capped at 4 KiB / 64 reads.
- Fail-closed config: empty/placeholder `[masking] enabled = true` without
  valid credentials must fail at config load.
- Tests: no fixed-sleep synchronization (AGENTS.md §5); poll-with-timeout or
  `join_next()` drains only.
- `deny.toml`: add `chacha20` (and its `cpufeatures`/`cfg-if` deps) to the
  license audit.

## 10. Test matrix summary

| Area | Cases |
|------|-------|
| Prelude codec | round-trip, 7-bit edges, non-canonical rejects, policy vectors |
| Keystream | partial-write rollback, short reads, 2^38−64 cap, concurrent dirs |
| Replay | dup/zero/window-edge/evict/re-register, 2-phase commit ordering |
| Integration | SOCKS TCP+UDP over masked TLS; masked QUIC; carrier fallback |
| Probing | silent-drop (TCP), no-VN (UDP), no rustls invocation, deadline |
| Timing | unknown-key_id uniformity (SEC-08 style) |
| Config | whitelist, fail-closed, Helm render → binary config-check |
| Reload | SIGHUP swaps mask keys for new connections only |

## 11. Risks & accepted limits

| Risk | Mitigation |
|------|------------|
| Keystream desync on partial writes (the classic bug class of stream masks) | offset tracking + `try_seek` rollback; dedicated property tests (1a); this is the highest-implementation-risk item |
| GRO/GSO platform variance | Linux CI exercises multi-segment; macOS local single-segment; explicit `RecvMeta` rewrite tests |
| Credential-holders can burn/churn replay windows; registry restart wipes history | Documented limit (inherited from the construction); registry size bounded; only reachable *with* a valid key |
| Captured prelude allows offline key guessing | 14-byte tag = 112-bit HMAC; equivalent to guessing the secret itself; document |
| Timing side channel in try-all-credentials | Padded constant-cost loop (existing `uk-auth` pattern); cap credential count when masking on |
| QUIC MTU reduction shrinks DATAGRAM ceiling | Documented in tuning docs; 12 B delta |
| Cert-signature DoS replaced by HMAC DoS floor | Adversary saves cost too, but per-probe server cost drops from ms to µs — net win for the defender; limiter still applies |

## 12. Effort summary

| Phase | Scope | Effort |
|-------|-------|--------|
| 0 | RFC, spec, vectors, threat-model | 2–3 d |
| 1a | TCP masking core (server+client) | 8–10 d |
| 1b | Silent acceptor, policies, fuzz pass | 3–4 d |
| 2 | QUIC/UDP masking | 6–8 d |
| 3 | Helm, docs, benchmarks, release | 4–5 d |
| **Total** | | **~5–6 weeks single-threaded** |

Each phase lands green independently (tests + clippy `-D warnings` +
`cargo deny` + Helm config-check + docker smoke), and Phases 1a/1b/2 each
ship behind the default-off flag, so trunk stays releasable throughout.

## 13. Rejected / deferred alternatives

- **uTLS-style fingerprint mimicry** — replaces rustls ClientHello
  generation; enormous surface, brittle, conflicts with G4. Rejected.
- **Nowhere wire compatibility** — single-shared-key auth vs. UK
  multi-credential; would force plaintext `key_id` or a shared master.
  Rejected (D5).
- **Default-on masking** — contradicts the "standard encrypted transports"
  positioning and complicates first-run experience. Revisit only with
  operator demand.
- **Padding/traffic shaping** (defeating volume analysis) — out of scope;
  non-goal §3.
- **Encrypted SNI / outer TLS fronting (trojan/naive-style decoy)** —
  requires a fronting domain and public web infrastructure; different threat
  model. Deferred indefinitely.
