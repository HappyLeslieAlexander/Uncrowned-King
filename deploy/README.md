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
  `allowPrivilegeEscalation: false`, all capabilities dropped, and the
  `RuntimeDefault` seccomp profile.
- **Probes**: `livenessProbe` → `/healthz`, `readinessProbe` → `/readyz` on the
  metrics port (9090). The config binds `observability_listen` to `0.0.0.0:9090`
  so the kubelet can reach the probes; the Service does **not** expose 9090.
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
metal) or off the public Service (Kubernetes). Prometheus alert rules and a
Grafana dashboard for the exported metrics live in
[`../deploy/monitoring/`](monitoring/); the operations runbook is
[`../docs/operations.md`](../docs/operations.md).
