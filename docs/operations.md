# Operations Runbook

Operating the Uncrowned King server and client in production. See also
[`deploy/`](../deploy/) for systemd and Kubernetes manifests,
[`docs/key-management.md`](key-management.md) for secrets, and
[`docs/performance.md`](performance.md) for tuning data.

## Deployment preflight

- Validate config before every start/rollout: `uk-server --config … config-check`
  (and the client equivalent). It checks the config, credentials, policy, and
  TLS files without listening.
- Secrets and keys must be `0600`/`0640` and owned by the service user; the
  process refuses to start otherwise (Unix).
- Keep `/metrics` (and the whole observability listener) off the public network
  — it is unauthenticated. Bind it to loopback (bare metal) or leave it out of
  the Service (Kubernetes); the kubelet still reaches it in-pod for probes.

## Capacity planning

The server enforces bounded resources; size them to the host and expected load:

| Limit | Governs | Scale with |
| --- | --- | --- |
| `max_sessions` | authenticated carrier sessions | expected concurrent clients |
| `max_handshakes` | in-flight unauthenticated handshakes | connection arrival burst |
| `max_streams` / `max_udp_flows` | flows per session | per-client concurrency |
| `max_outbound_dials_per_session` | concurrent target dials | target fan-out |
| `max_buffered_bytes_per_session` / `_per_flow` | queued server→client bytes (also sizes the per-flow queue) | bandwidth-delay product |
| `LimitNOFILE` (systemd) | file descriptors | ~2 per flow + sockets |

Rules of thumb: each active flow uses ~2 sockets and up to
`max_buffered_bytes_per_flow` of memory; a soak of 16 sustained flows held RSS
around 70 MiB (see `docs/performance.md`). Set `LimitNOFILE` well above
`2 × max_sessions × max_streams`.

## Tuning

- **Throughput of a single bulk flow** is bounded by `max_buffered_bytes_per_flow`
  (the per-flow queue is derived from it). Raise it for high bandwidth-delay
  links; a single flow is shed only after buffering its full byte budget. Bulk
  and latency-sensitive traffic on one TLS/TCP carrier still share that budget —
  prefer QUIC, which paces per-stream.
- **Idle/timeout knobs** (`idle_timeout_seconds`, `handshake_timeout_seconds`,
  `target_connect_timeout_seconds`, `tcp_half_close_timeout_seconds`,
  `udp_flow_idle_timeout_seconds`, `shutdown_timeout_seconds`) trade resource
  reclamation against tolerance for slow peers. `0` disables each.
- Reloadable via SIGHUP: credentials, policy, and the TLS/QUIC identity.
  **Not** reloadable (need a restart): `listen`, `quic_listen`, all limits and
  timeouts, and the observability listener.

## Alerts → likely cause → action

Alerts are defined in [`deploy/monitoring/prometheus-alerts.yaml`](../deploy/monitoring/prometheus-alerts.yaml).

| Alert | Likely cause | Action |
| --- | --- | --- |
| `UncrownedKingServerNotReady` / `…Down` | shutting down, crashed, or unreachable | check logs / restart; verify scrape target |
| `…HandshakeFailureSpike` | wrong CA/cert, clock skew, bad/rotated secret, or a scanner | inspect `handshake_failures_total` by reason (tls/auth/protocol/timeout); rotate/repair the offending material |
| `…HandshakeLimitSaturation` | `max_handshakes` too low or a connection flood | raise `max_handshakes` (restart) or scale out; check for abuse |
| `…SessionLimitSaturation` | `max_sessions` too low | raise `max_sessions` (restart) or scale out |
| `…FlowOpenFailureSpike` | policy denials, resource limits, or unreachable targets | check policy, limits, and target health |
| `…ConfigReloadFailed` | invalid candidate config/cert/key | the running config is unchanged; fix the candidate and reload again (`server.config.reload_failure` in logs) |

## Certificate and credential rotation

Zero-downtime rotation and revocation are in
[`docs/key-management.md`](key-management.md). In short: add a new credential →
roll clients → retire the old; and for the identity, install the new cert/key
and `systemctl reload` (or SIGHUP) — new connections use the rotated identity,
existing ones keep theirs. Confirm success via the `server.config.reload_success`
log event and the reload-success metric before retiring old material.

## Upgrades and rollback

1. Read the [`CHANGELOG.md`](../CHANGELOG.md) for the target version.
2. Roll out one instance (canary), watch readiness, handshake-failure rate,
   rejection rates, and relay throughput.
3. Promote gradually; the server drains gracefully on SIGTERM within
   `shutdown_timeout_seconds` before aborting remaining tasks.
4. **Rollback**: redeploy the previous image/binary and previous config. Config
   is backward-loadable across patch versions; if a config field changed, roll
   the config back with the binary. Existing connections drop on restart and
   clients reconnect (with carrier fallback).

## Graceful shutdown

Both binaries stop on Ctrl+C/SIGTERM: readiness drops first (so load balancers
stop sending traffic), then in-flight sessions drain up to
`shutdown_timeout_seconds`, then remaining tasks are aborted. Set
`shutdown_timeout_seconds = 0` to wait indefinitely.
