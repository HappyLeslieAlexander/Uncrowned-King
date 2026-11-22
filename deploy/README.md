# Deploying Uncrowned King

Two supported deployment tracks. Both run the process **unprivileged** and read
config/keys from a directory the process cannot write.

Always validate configuration before starting:

```sh
uk-server --config server.toml config-check
uk-client --config client.toml config-check
```

## Bare metal / VM (systemd)

Hardened units are in [`systemd/`](systemd/). They run as a dedicated
`uncrowned-king` system user with `NoNewPrivileges`, `ProtectSystem=strict`, an
empty capability set, a `@system-service` syscall filter, and bounded
`LimitNOFILE`/`TasksMax`. Install steps are in the header of each unit file:

- [`systemd/uncrowned-king-server.service`](systemd/uncrowned-king-server.service)
- [`systemd/uncrowned-king-client.service`](systemd/uncrowned-king-client.service)

Install the config files and the server private key mode **`0600`**. The process
rejects any file with a group or other permission bit set (`0640` and `0644`
fail at startup), so an install that looks conventional will not boot.

The units allow `AF_UNIX` and `AF_NETLINK` in addition to `AF_INET`/`AF_INET6`:
a glibc-linked binary — which is what the units' own build-from-source install
steps produce — needs them to resolve hostnames via `nsswitch.conf` backends
(systemd-resolved/nscd) and for source-address selection. The published static
musl release binaries do not, but keeping them costs nothing.

Reload credentials, policy, and the TLS/QUIC identity without dropping
connections:

```sh
sudo systemctl reload uncrowned-king-server
```

To listen on a port below 1024, add `AmbientCapabilities=CAP_NET_BIND_SERVICE`
to the unit (and don't remove it from the bounding set); otherwise no
capabilities are needed.

## Kubernetes

[`kubernetes/uncrowned-king-server.yaml`](kubernetes/uncrowned-king-server.yaml)
is a complete server deployment: Namespace, a policy ConfigMap, a Secret holding
`server.toml` + certificate + key, a hardened Deployment, and a Service exposing
the TCP and UDP (QUIC) carrier ports.

Key points:

- **Security context**: `runAsNonRoot` (uid 65532), `readOnlyRootFilesystem`,
  `allowPrivilegeEscalation: false`, all capabilities dropped,
  `automountServiceAccountToken: false`, and the `RuntimeDefault` seccomp
  profile.
- **Config staging (do not "simplify")**: an `initContainer` copies the Secret
  and policy ConfigMap into a memory-backed `emptyDir` and `chmod 0600`s them;
  the server mounts only that copy. A Secret cannot be mounted directly at an
  acceptable mode: under `fsGroup` the kubelet projects it as `root:65532` mode
  `0440`, and the server rejects any group/other bit; without `fsGroup` it is
  `root:root` `0400` and uid 65532 cannot read it at all.
- **Secret/policy changes need a pod roll**: because the files are copied at pod
  start, SIGHUP hot-reload cannot see an edited Secret or ConfigMap in this
  manifest. Apply changes with `kubectl rollout restart deployment/uncrowned-king-server`
  (the rollout strategy and PodDisruptionBudget keep capacity during the roll).
- **Probes**: `livenessProbe` → `/healthz`, `readinessProbe` → `/readyz` on the
  metrics port (9090). The template stages `observability_listen` bound to the pod's IP
  via Downward API (`status.podIP`) so the kubelet and internal Prometheus can reach the probes;
  the Service does **not** expose 9090. Wildcard binds (`0.0.0.0`) are strictly rejected.
- **Secrets**: replace every `REPLACE_ME` with real values. In practice, build
  the Secret out of band (e.g. `kubectl create secret …`) and keep it out of
  version control.
- The image comes from `.github/workflows/release.yml`
  (`ghcr.io/happylesliealexander/uncrowned-king-server`).

Apply:

```sh
kubectl apply -f deploy/kubernetes/uncrowned-king-server.yaml
```

The client is analogous: mount a `client.toml` and the CA certificate, expose
the SOCKS5 port only where you enforce your own access control (or keep it a
sidecar/loopback listener).

## Observability

The metrics endpoint (`/metrics`) is unauthenticated — keep it on loopback (bare
metal) or off the public Service (Kubernetes). Prometheus alert rules, an
Alertmanager routing example, and a Grafana dashboard for the exported metrics
live in [`../deploy/monitoring/`](monitoring/); the operations runbook is
[`../docs/operations.md`](../docs/operations.md).

## Going live

[`../docs/launch-gate.md`](../docs/launch-gate.md) covers the release gate:
SLOs, canary rollout with promote/abort criteria, the rollback playbook,
alert-delivery verification, and a go-live checklist. The K8s Deployment ships
with a safe rollout strategy (`maxUnavailable: 0`, surge one, `minReadySeconds`)
and a PodDisruptionBudget so a canary never drops capacity.
