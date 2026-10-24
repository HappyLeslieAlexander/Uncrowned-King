# Operations Runbook

Operating the Uncrowned King server and client in production. See also
[`deploy/`](../deploy/) for systemd and Kubernetes manifests,
[`docs/key-management.md`](key-management.md) for secrets, and
[`docs/performance.md`](performance.md) for tuning data.

## Deployment preflight

- Validate config before every start/rollout: `uk-server --config … config-check`
  (and the client equivalent). It checks the config, credentials, policy, and
  TLS files without listening.
- Secrets and keys must be `0600` and owned by the service user; the process
  refuses to start otherwise (Unix). Any group or other permission bit is
  rejected — `0640` and `0644` do **not** work.
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
| `max_buffered_bytes_per_session` / `_per_flow` | queued client→target bytes for one session/flow | bandwidth-delay product |
| `max_total_buffered_bytes` / `max_total_streams` | global server-wide buffered bytes and concurrent flows | host memory and file-descriptor budget |
| `LimitNOFILE` (systemd) | file descriptors | ~2 per flow + sockets |

Rules of thumb: each active flow uses ~2 sockets and up to
`max_buffered_bytes_per_flow` of memory; a soak of 16 sustained flows held RSS
around 70 MiB (see `docs/performance.md`). Size `max_total_buffered_bytes` below
the process memory limit and set `LimitNOFILE` above the global flow budget
(roughly `2 × max_total_streams`).

## Authentication rate limiting

Failures are aggregated per IPv4 source address, per IPv6 `/64` prefix, and
therefore per NAT egress: with the default `5 failures / 60s -> 300s ban`,
five failed handshakes from *any* client behind one shared NAT (or inside one
IPv6 `/64`) ban *all* of them for five minutes. If your clients egress
through a known NAT or a prober triggers handshakes from a fixed address,
exempt those sources in `[limits]`:

```toml
auth_rate_limit_allowlist = ["198.51.100.0/24", "203.0.113.7"]
```

Allowlisted sources skip failure counting and banning entirely; everyone else
keeps full brute-force protection. Changing the list requires a restart.

## Tuning

- **Throughput of a single bulk flow** is bounded by `max_buffered_bytes_per_flow`
  (the per-flow queue is derived from it). Raise it for high bandwidth-delay
  links; a single flow is shed only after buffering its full byte budget. Bulk
  and latency-sensitive traffic on one TLS/TCP carrier still share that budget —
  prefer QUIC, which paces per-stream.
- **Idle/timeout knobs** (`idle_timeout_seconds`, `handshake_timeout_seconds`,
  `target_connect_timeout_seconds`, `tcp_half_close_timeout_seconds`,
  `carrier_write_timeout_seconds`, `tcp_keepalive_seconds`,
  `udp_flow_idle_timeout_seconds`,
  `shutdown_timeout_seconds`) trade resource reclamation against tolerance for
  slow peers. `0` disables each. `carrier_write_timeout_seconds` is the one that
  bounds a peer which stops reading: without it such a client pins its session
  slot indefinitely, so raise it for genuinely slow links rather than disabling
  it. A breach is logged as `server.carrier.write_timeout` and closes the
  session (`server.session.carrier_failed`). `tcp_keepalive_seconds` covers the
  other half — a peer that vanished without closing, which no write deadline can
  see because there is nothing to write.
- **QUIC flow control receive windows** (`limits.quic_stream_receive_window` and
  `limits.quic_connection_receive_window`, default 1 MiB each, valid range 64 KiB
  to 16 MiB, with connection window ≥ stream window) govern Quinn transport
  buffering for QUIC carriers. Raise them on high-BDP (bandwidth-delay product)
  links to prevent transport-level flow control stalls. Like other limits, changes
  require a restart.
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
