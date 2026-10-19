# Uncrowned King — Development Guidelines & Production Guardrails

This document establishes the non-negotiable architectural invariants, security policies, and deployment rules for the `Uncrowned King` (UK) codebase. All agents and contributors must strictly adhere to these principles.

---

## 1. Code Integrity & Safety Invariants

- **Strict Zero Unsafe (`unsafe_code = "forbid"`)**:
  - The workspace strictly prohibits `unsafe` code across all crates.
  - Never introduce `unsafe` blocks, `std::mem::transmute`, unchecked pointer dereferences, or foreign functions without explicit workspace-wide policy exemption.

- **Constant-Time Cryptography & Anti-Side-Channel**:
  - All HMAC verification and Key ID matching in `uk-auth` must execute in constant time (`subtle::ConstantTimeEq`).
  - When an unknown `key_id` is supplied, execute a dummy HMAC calculation to maintain constant execution duration and avoid timing leaks.

- **Canonical Varint & Bounded Memory Allocation**:
  - Frame headers and payload length prefixes in `uk-proto` must strictly adhere to RFC 9000 §16 canonical Varint encoding (reject non-minimal encodings).
  - Stream and frame readers must read payloads in bounded chunks (e.g. 256 KB `READ_RESERVE_CHUNK`) to prevent memory exhaustion DoS from maliciously inflated headers.

---

## 2. Security & Policy Enforcement Guardrails

- **Secure-by-Default Access Control (`uk-policy`)**:
  - Any `Allow` rule in `PolicyRule` must default to rejecting private/loopback IPs (`private = Some(false)`) unless explicitly configured with `private = true`.
  - Cloud provider metadata service addresses (AWS/GCP `169.254.169.254`, Alibaba Cloud `100.100.100.200`, Azure WireServer `168.63.129.16`, AWS IPv6 `fd00:ec2::254`) must be permanently rejected before evaluating any user-defined rules.
  - Domain validation must strictly reject IP literal strings (`"127.0.0.1"`, `"::1"`) passed as `Target::Domain` to prevent policy bypass.

- **Atomic Reload & State Isolation**:
  - SIGHUP configuration reloads must atomically swap TLS acceptors and authentication state for *new* connections without interrupting or modifying already accepted connection contexts.

---

## 3. Concurrency, Transport & Lifecycle Management

- **Graceful Shutdown & Connection Draining (`uk-server`)**:
  - Server shutdown upon `SIGTERM` or `Ctrl+C` must execute a graceful drain phase: stop accepting new connections, signal downstream clients, and allow active flows a configurable timeout period (default 30s) to terminate cleanly before hard cancellation.
  - Never drop reader/writer tasks instantaneously without draining active flows.

- **Transport Resilience & Reconnection Discipline (`uk-client`)**:
  - Reconnection logic must implement exponential backoff with randomized jitter. Avoid fixed-interval reconnection loops (e.g. static 250ms) to prevent thundering herd storms against recovering servers.
  - Cache carrier availability: if QUIC/UDP is unreachable or filtered, remember degraded state to avoid repetitive 10-second handshake timeouts.

---

## 4. Operational Readiness & Deployment Standards

- **Strict File Permissions (`mode & 0o077 == 0`)**:
  - Server strictly enforces that configuration files and certificates have no group or other permissions (e.g. `0600` or `0400`).
  - **Kubernetes / Helm Manifests**: ConfigMaps are mounted with `0644` by default; deployment templates must use an `initContainer` to copy and `chmod 0600` configuration files into a shared emptyDir volume before the main container starts.
  - **Zero Plaintext Secrets**: Authentication keys and private keys must never be placed in plain `ConfigMap` templates. Always use Kubernetes `Secret` resources or external secret stores.

- **Prometheus & Observability Standards**:
  - All metrics exported via the `/metrics` endpoint must strictly follow Prometheus text format conventions (including `# HELP` and `# TYPE` declarations).
  - Internal management and metrics endpoints (`:9090`) must bind to internal cluster networks only and never be exposed on public LoadBalancer services.
