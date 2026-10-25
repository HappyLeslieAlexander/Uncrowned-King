# uk-client audit evidence — 2026-09-09

All production sources were left unchanged. Experiments run on an isolated copy at `/tmp/uk-client-audit-20260909`, including the workspace's current `.cargo/config.toml` (`-Dunsafe-code`).

`audit-tests.patch` adds only three regression tests to `crates/uk-client/src/relay/tests.rs`. `audit-ca-one.pem` and `audit-ca-two.pem` are pre-existing synthetic test certificates extracted from `tcp_relay_e2e.rs`; place them at the isolated workspace root. They are test trust fixtures, not production credentials.

Reproduce in a fresh isolated copy of the reviewed tree containing Cargo.toml, Cargo.lock, .cargo/, crates/, and examples/:

```sh
patch -p1 < /path/to/audit-tests.patch
cp /path/to/audit-ca-one.pem /path/to/audit-ca-two.pem .
cargo test -p uk-client --lib audit_ -- --nocapture
```

Expected observed result on the reviewed implementation: exit 101, 3 failed. Assertions express the required correct behavior, so these failures demonstrate defects:

1. `audit_udp_control_reset_leaves_orphan_route`: opens a real loopback TCP control connection, creates a UDP flow over an in-memory mock carrier, sends TCP RST via SO_LINGER=0, awaits relay task exit. Observed `routes retained=1, available_udp_permits=8`; route should be removed.
2. `audit_udp_old_session_completion_must_not_remove_new_session_flow`: reserves the first UDP flow in two distinct sessions (both id=1), installs the newer target mapping, delivers the older completion. New mapping is incorrectly removed. This deterministically models completion queued while the association's failed-send retry reconnects to a new session.
3. `audit_rejected_reload_must_preserve_active_ca_cache`: loads CA A, replaces same-path file with CA B, requests a reload changing restart-only max_socks_connections. Observed rejection, generation=1, but shared TLS cache pointer changed. The checked code reloads CA B into this cache before checking restart compatibility.

Logs: `reproduction.log` contains all three regression failures; `existing-client-unit-tests.log` confirms all 255 pre-existing client library tests pass (`cargo test -p uk-client --lib -- --skip audit_`, exit 0).

Source lines in the reviewed workspace:

- UDP exceptional cleanup: relay/udp.rs:196-198 and 205-214 bypass close at 236; relay/context.rs:288-291 only drops metric guard. Stale route ceilings are enforced by relay/session_manager.rs:1476-1481.
- UDP completion identity: relay/udp.rs:470-471 and 487-490 compare only target and flow_id; session_manager.rs:727 restarts IDs per session. Activity events at udp.rs:497-505 have the same identity weakness.
- Rejected reload changes trust cache: relay/session_manager.rs:185-192 validates before checking compatibility; lib.rs:89 calls tls::connector; tls.rs:64-66 overwrites the shared path-keyed cache. New connections consult it at tls.rs:37-39.

Scope limitations: synthetic carrier for the reset test, deterministic completion delivery for the identity race, and cache-state inspection for the CA test. These are targeted local regressions, not WAN chaos testing, production load testing, or a full certificate handshake in the rejected-reload test.
