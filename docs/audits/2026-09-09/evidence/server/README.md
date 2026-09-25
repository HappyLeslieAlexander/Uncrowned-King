# Server review evidence — 2026-09-09

Source evaluated: current working tree, including the user’s existing changes to `relay/tasks.rs`, `relay/tests.rs`, and `tests/adversarial_sec_challenge.rs`. No project source files were changed by this audit.

`server-review-tests.patch` adds review tests only. `server-review-tests.log` is the actual output (five intentional regression assertion failures). Run `sh /absolute/path/to/reproduce.sh /absolute/path/to/project` to create a temporary source copy, apply the tests, and execute them. The shared target directory is used only as a build cache.

## Confirmed through isolated component reproduction

1. `review_drain_drops_data_after_both_half_closes`: stages a valid scheduling condition where the target has half-closed its send side, 18 client bytes are queued, and client normal close has made the flow table empty before the target writer gets scheduled. The actual `close_session` and actual TCP target writer run. Target receives **0 of 18 bytes**. Relevant source: `context.rs:739-742`, `tcp.rs:301-317`, `session.rs:135-138,267-269`, `tasks.rs:481-503`. Additional stronger reproduction: `review_real_relay_drain_loses_tail_of_upload` runs the complete production `relay_session` state machine with a real TCP target (an in-memory duplex stream substitutes only for the already-authenticated carrier). With default 64 KiB frame size, default 2 MiB per-flow queue, and 30-second drain timeout, target sends its FIN, client uploads 1 MiB during drain then normal CLOSE, and target delays reads by only 50 ms. Server returns `Ok(())`, but target receives **0 of 1,048,576 bytes** (reproduced twice). No TLS/QUIC authentication was included in this reproduction. Data loss applies when these conditions overlap with graceful shutdown; it does not claim every shutdown loses data.

2. `review_closed_flows_leave_half_close_timers`: with `max_streams=1`, cycles 100 flows through real open-slot checks and real read/write-closed handlers. All table entries disappear but **100 live 30-second timers** remain. Relevant source: `tasks.rs:434-459`; timers only observe session shutdown and never flow completion. This establishes task accumulation beyond the configured concurrent-flow count, not a measured process OOM.

3. `review_aborted_flow_still_sends_queued_data`: holds the real carrier writer lock while an actual TCP reader obtains old target data. After flow abort, releasing the lock still emits the old DATA frame. Relevant source: `tasks.rs:547-559`, `session.rs:784-795`. It proves emission after abort. Misdelivery on an ID reuse requires the peer to reuse an ID; that further end-to-end consequence was not reproduced. Protocol code accepts reused IDs after table removal, but the bundled client normally increments IDs.

## Additional component risk; remote trigger not verified

4. `review_settings_write_holds_session_after_shutdown`: injects a never-ready AsyncWrite at the authenticated carrier boundary. SETTINGS holds the only session permit and ignores a shutdown signal. Relevant source: `lib.rs:966-967,1004-1019,1251-1276`. This confirms missing deadline/cancellation on the writer abstraction. A QUIC peer selectively withholding flow-control credit is a plausible remote trigger, but a real TCP/QUIC exploit was not executed; do not describe this as remotely reproduced.

## Static follow-up risk; no attack reproduction

DNS resolution runs before outbound dial permits (`dialer.rs:70-81,104-115,117-125`). Tokio 1.52.3 implements domain lookup with `spawn_blocking(std::net::ToSocketAddrs)` (`tokio/src/net/addr.rs:192-222`). Canceling pending OPEN futures cannot stop already running blocking resolution. A bounded resolver queue and permit lifetime covering uncancelable resolver work deserve testing under DNS delays; do not claim a measured DNS flood or OOM.
