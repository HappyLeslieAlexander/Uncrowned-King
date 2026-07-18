# Launch Gate

The final gate before GA. It defines how a release reaches production safely:
canary rollout, the promote/abort decision, the rollback playbook, alerting
integration, and a sign-off checklist. It builds on
[`docs/operations.md`](operations.md) (day-2 operations) and the manifests in
[`deploy/`](../deploy/).

All decision thresholds below key off metrics the server actually exports
(`uncrowned_king_server_*`, see `crates/uk-server/src/observability.rs`) and the
`/readyz` probe.

## Service level objectives

Define the SLOs the rollout is gated on. Starting targets (tune to your load):

| SLO | Target | Metric |
| --- | --- | --- |
| Availability | `/readyz` up ≥ 99.9% | `uncrowned_king_server_ready` / probe |
| Handshake success | ≥ 99% of accepted connections | `1 - rate(failed_handshakes_total) / rate(accepted_connections_total)` |
| Admission (not limit-shedding) | ~0 sustained rejects | `rate(rejected_handshakes_total)`, `rate(rejected_sessions_total)` |
| Flow-open success | ≥ 99% (excluding policy denials) | `rate(flow_open_failures_total) / rate(flow_open_requests_total)` |

## Canary rollout

The K8s manifest is configured for a safe rollout out of the box:
`strategy: RollingUpdate` with `maxUnavailable: 0` / `maxSurge: 1`,
`minReadySeconds: 10`, and a `PodDisruptionBudget` of `minAvailable: 1`. A new
pod receives traffic only after it passes `/readyz`, and the old pod is not
removed until then.

1. **Deploy one canary.** Push the new image tag and update the Deployment. With
   `maxUnavailable: 0` the rollout surges one new pod, waits for readiness +
   `minReadySeconds`, then retires an old one — one pod at a time.
   - Bare metal: upgrade a single instance behind the load balancer first.
2. **Soak and observe** for a fixed window (e.g. 15–30 min) against the SLO
   table. Watch the Grafana dashboard: readiness, handshake-failure rate,
   rejection rates, flow-open failures, relay throughput.
3. **Promote** if every SLO holds: let the rollout continue to the remaining
   replicas (`kubectl rollout status deploy/uncrowned-king-server -n uncrowned-king`).
4. **Abort** on any SLO breach or a firing critical alert → roll back (below).

Promote/abort criteria at the canary step:

| Signal | Promote | Abort |
| --- | --- | --- |
| `/readyz` | steadily 1 | flaps or stays 0 past `initialDelay` |
| Handshake failures | within SLO | `HandshakeFailureSpike` fires |
| Rejections | ~0 sustained | limit-saturation alert fires (and not a real capacity change) |
| Flow-open failures | within SLO | `FlowOpenFailureSpike` fires |
| Logs | clean | repeated `server.config.*` / panic / handshake errors |

## Rollback playbook

Rollback is always to the **previous image/binary + previous config together**
(config may have changed with the binary). Existing connections drop on restart;
clients reconnect with carrier fallback (QUIC → TLS).

- **Kubernetes:**
  ```sh
  kubectl rollout undo deploy/uncrowned-king-server -n uncrowned-king
  kubectl rollout status deploy/uncrowned-king-server -n uncrowned-king
  ```
  If the config (Secret/ConfigMap) changed in this release, restore the previous
  Secret/ConfigMap first, then `rollout undo`.
- **systemd / bare metal:** repoint `/usr/local/bin/uk-server` to the previous
  binary, restore the previous `/etc/uncrowned-king/` files, then
  `systemctl restart uncrowned-king-server`. Validate first with
  `uk-server --config /etc/uncrowned-king/server.toml config-check`.
- **Config-only regression** (identity/policy/credentials, binary unchanged):
  restore the previous files and `systemctl reload` (or SIGHUP) — no restart, no
  dropped connections. A bad candidate is rejected atomically and the running
  config is unchanged (`ConfigReloadFailed` alert / `server.config.reload_failure`).

Confirm recovery: `/readyz` green, SLO metrics back to baseline, critical alerts
resolved.

## Alerting integration and delivery verification

1. Load the rules into Prometheus (`rule_files:` or a `PrometheusRule` CRD) from
   [`deploy/monitoring/prometheus-alerts.yaml`](../deploy/monitoring/prometheus-alerts.yaml)
   and confirm they load: `promtool check rules …`.
2. Route them in Alertmanager using
   [`deploy/monitoring/alertmanager-example.yaml`](../deploy/monitoring/alertmanager-example.yaml)
   as a template: critical → pager, warning → chat.
3. **Verify delivery end to end before go-live** — do not assume wiring works.
   Send a synthetic alert and confirm it pages, then resolve it (commands are in
   the header of the Alertmanager example). Verify a warning reaches chat too.
4. Confirm the Prometheus scrape target is the in-pod/loopback metrics endpoint,
   not a public one — `/metrics` is unauthenticated.

## Go-live checklist (sign-off)

Gate the release on all of the following. Record who signed and when.

**Functionality & security**
- [ ] MVP §19 suite green on the release commit, including QUIC DATAGRAM.
- [ ] Threat model reviewed; `cargo-deny` + audit + fuzz smoke green in CI.
- [ ] TLS identity and credentials issued per [`docs/key-management.md`](key-management.md); files `0600`/`0640`, owned by the service user.
- [ ] Policy denies private/reserved ranges first; allow-list scoped to real targets.

**Release artifacts**
- [ ] Tagged release built by `release.yml`: binaries + checksums + multi-arch image + SBOM + cosign signatures.
- [ ] Image digest pinned for the rollout; signature/SBOM attestation verified.

**Deploy & operate**
- [ ] `config-check` passes for the production config on both server and client.
- [ ] One clean deploy rehearsed in **each** form (container + bare metal).
- [ ] `/metrics` off the public network; `/healthz` + `/readyz` probes wired.
- [ ] Capacity limits sized to the host (`docs/operations.md` capacity table); `LimitNOFILE` set.

**Observability & rollout**
- [ ] Dashboard live; SLOs defined with owners.
- [ ] Alert rules loaded; **synthetic alert delivered end to end** (page + chat) and resolved.
- [ ] Canary plan and abort criteria agreed; rollback rehearsed (`rollout undo` / previous binary).
- [ ] On-call informed; runbook ([`docs/operations.md`](operations.md)) linked from the alert annotations.

**Sign-off:** _release ___ · owner ___ · date ___ · approver ____
