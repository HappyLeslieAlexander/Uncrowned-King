"""Tier 1 (Feature Tests) for Uncrowned King Production Hardening (R1-R6).

36 opaque-box E2E tests (6 per requirement R1-R6) exercising compiled
`uk-server` and `uk-client` binaries, pure-Python wire probes (`uk_wire.py`),
SOCKS5 TCP/UDP relay, Prometheus `/metrics`, `/readyz`, and `./scripts/helm-config-check.sh`.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple

from uk_harness import (
    E2ETestCase,
    LocalHttpServer,
    LocalTcpEchoServer,
    LocalUdpEchoServer,
    TestContext,
    UkClientProcess,
    UkServerProcess,
    allow_loopback_policy,
    build_client_toml,
    build_server_toml,
    deterministic_bytes,
    discover_loopback_sources,
    format_host_port,
    free_tcp_port,
    free_udp_port,
    http_get,
    make_secret,
    parse_prometheus_metrics,
    run_client_handshake,
    run_config_check,
)
from uk_wire import (
    ChaCha20Stream,
    CloseKind,
    MaskKeys,
    MaskedTcpProbe,
    ProbeResult,
    QuicProbeSocket,
    Socks5Client,
    StallProxy,
    TransparentFirstSegmentProxy,
    UdpObserverProxy,
    WIRE_PRELUDE_LEN,
    build_oversized_client_hello,
    build_quic_initial_probe,
    build_tls12_client_hello,
    build_tls13_client_hello,
    build_tls_alert_record,
    check_socket_closed,
    derive_mask_keys,
    encode_prelude,
    read_first_response,
    read_until_close,
)


# ---------------------------------------------------------------------------
# Local Helpers
# ---------------------------------------------------------------------------

def _assert_server_hello(res: ProbeResult, context: str = "") -> None:
    prefix = f"{context}: " if context else ""
    assert len(res.received) >= 6, (
        f"{prefix}expected decrypted ServerHello (>=6 bytes), got {len(res.received)} bytes "
        f"(raw={len(res.raw_received)}, close={res.close_kind}, err={res.error})"
    )
    assert res.received[0] == 0x16 and res.received[1:3] == b"\x03\x03", (
        f"{prefix}expected TLS Handshake record 16 03 03, got {res.received[:6].hex()}"
    )
    assert res.received[5] == 0x02, (
        f"{prefix}expected TLS ServerHello (0x02), got handshake type 0x{res.received[5]:02x}"
    )


def _assert_silent_rst(res: ProbeResult, context: str = "") -> None:
    prefix = f"{context}: " if context else ""
    assert len(res.raw_received) == 0, (
        f"{prefix}expected 0 wire bytes on silent rejection, got {len(res.raw_received)} bytes: "
        f"{res.raw_received[:32].hex()}"
    )
    assert res.close_kind == CloseKind.RST, (
        f"{prefix}expected abortive close (RST), got {res.close_kind} (elapsed={res.elapsed_s:.3f}s)"
    )


def _close_all(sockets: List[socket.socket]) -> None:
    for s in sockets:
        try:
            s.close()
        except OSError:
            pass


def _find_pre_admission_reject_metric(metrics_text: str) -> Optional[float]:
    parsed = parse_prometheus_metrics(metrics_text)
    total = 0.0
    found = False
    for (name, _labels), val in parsed.items():
        if ("pre_auth" in name or "pre_admission" in name) and (
            "reject" in name or "drop" in name or "limit" in name
        ):
            total += val
            found = True
    return total if found else None


_UdpObserverProxy = UdpObserverProxy


_DEFAULT_MASKING = object()


def _setup_masked_tcp_server(
    ws,
    ctx: TestContext,
    *,
    limits: Optional[Dict[str, object]] = None,
    masking: object = _DEFAULT_MASKING,
    credentials: Optional[List[Dict[str, object]]] = None,
    listen_host: str = "127.0.0.1",
    quic_port: Optional[int] = None,
    policy_ports: Optional[List[int]] = None,
) -> Tuple[UkServerProcess, int, int, List[Dict[str, object]]]:
    certs = ws.generate_certs()
    if credentials is None:
        credentials = [{"key_id": "k1", "secret": make_secret()}]
    tcp_port = free_tcp_port(listen_host)
    obs_port = free_tcp_port("127.0.0.1")
    pol_path = ws.write_secret(
        "policy.toml", allow_loopback_policy(ports=policy_ports)
    )
    quic_listen = (
        format_host_port(listen_host, quic_port) if quic_port is not None else None
    )
    masking_cfg = {"enabled": True} if masking is _DEFAULT_MASKING else masking
    srv_cfg = ws.write_secret(
        "server.toml",
        build_server_toml(
            listen=format_host_port(listen_host, tcp_port),
            quic_listen=quic_listen,
            observability_listen=f"127.0.0.1:{obs_port}",
            cert_path=certs.cert,
            key_path=certs.key,
            policy_path=pol_path,
            credentials=credentials,
            limits=limits,
            masking=masking_cfg,  # type: ignore[arg-type]
        ),
    )
    srv = ws.enter(
        UkServerProcess(ctx.server_bin, srv_cfg, f"127.0.0.1:{obs_port}")
    )
    srv.wait_ready()
    return srv, tcp_port, obs_port, credentials


# ---------------------------------------------------------------------------
# R1: Replace CommitGate with rustls::server::Acceptor (6 tests)
# ---------------------------------------------------------------------------

def t1_r1_01_valid_prelude_corrupt_hello_silent_rst(ctx: TestContext) -> None:
    """Valid 76B prelude + corrupt ClientHello emits 0 bytes, dwells, closes via RST."""
    with ctx.workspace("t1_r1_01") as ws:
        srv, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        res = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=101,
            counter=1,
            plaintext_after_prelude=b"\x63" * 64,
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res, "corrupt ClientHello")
        assert 0.8 <= res.elapsed_s <= 3.5, (
            f"expected dwell within [0.8s, 3.5s] for timeout=2s, got {res.elapsed_s:.3f}s"
        )
        failed = srv.wait_for_metric(
            "uncrowned_king_server_failed_handshakes_total",
            lambda v: v >= 1,
            timeout=3.0,
        )
        assert failed >= 1


def t1_r1_02_valid_prelude_tls_alert_swallowed(ctx: TestContext) -> None:
    """TLS 1.2 ClientHello and raw TLS alert produce 0 response bytes, dwell, and RST."""
    with ctx.workspace("t1_r1_02") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])

        res_tls12 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=102,
            counter=1,
            plaintext_after_prelude=build_tls12_client_hello(),
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res_tls12, "TLS 1.2-only ClientHello")
        assert 0.8 <= res_tls12.elapsed_s <= 3.5, (
            f"TLS 1.2 dwell out of range: {res_tls12.elapsed_s:.3f}s"
        )

        res_alert = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=103,
            counter=1,
            plaintext_after_prelude=build_tls_alert_record(),
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res_alert, "raw TLS alert record")
        assert 0.8 <= res_alert.elapsed_s <= 3.5, (
            f"raw alert dwell out of range: {res_alert.elapsed_s:.3f}s"
        )


def t1_r1_03_corrupt_hello_does_not_burn_counter(ctx: TestContext) -> None:
    """Corrupt ClientHello after valid prelude (I, C) does NOT commit/burn counter C."""
    with ctx.workspace("t1_r1_03") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])

        res1 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=201,
            counter=7,
            plaintext_after_prelude=b"\x63" * 64,
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res1, "first corrupt ClientHello")

        res2 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=201,
            counter=7,
            plaintext_after_prelude=build_tls13_client_hello(),
            timeout=5.0,
            wait_for_close=False,
        )
        _assert_server_hello(res2, "retry same (I, C) with valid ClientHello")


def t1_r1_04_valid_hello_commits_counter_blocks_replay(ctx: TestContext) -> None:
    """Valid ClientHello commits (I, C); replaying same (I, C) is silently rejected."""
    with ctx.workspace("t1_r1_04") as ws:
        srv, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])

        res1 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=202,
            counter=9,
            plaintext_after_prelude=build_tls13_client_hello(),
            timeout=5.0,
            wait_for_close=False,
        )
        _assert_server_hello(res1, "initial valid ClientHello")

        res2 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=202,
            counter=9,
            plaintext_after_prelude=build_tls13_client_hello(),
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res2, "replayed (I, C) + valid ClientHello")
        replays = srv.wait_for_metric(
            "uncrowned_king_server_mask_replay_rejects_total",
            lambda v: v >= 1,
            timeout=3.0,
        )
        assert replays >= 1


def t1_r1_05_oversized_clienthello_over_64kib_rejected(ctx: TestContext) -> None:
    """68 KiB fragmented ClientHello is rejected silently (0B, RST); server stays healthy."""
    with ctx.workspace("t1_r1_05") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        oversized = build_oversized_client_hello(68 * 1024)
        res = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=203,
            counter=1,
            plaintext_after_prelude=oversized,
            timeout=6.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res, "68 KiB ClientHello")

        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                masking={"enabled": True},
            ),
        )
        cp = run_client_handshake(ctx.client_bin, cli_cfg)
        assert cp.returncode == 0, (
            f"legitimate uk-client handshake failed after oversized hello: {cp.stdout}\n{cp.stderr}"
        )


def t1_r1_06_bad_hello_increments_rate_limiter_to_ban(ctx: TestContext) -> None:
    """3 bad ClientHellos trigger AuthRateLimiter ban for 127.0.0.1."""
    with ctx.workspace("t1_r1_06") as ws:
        srv, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={
                "handshake_timeout_seconds": 1,
                "auth_rate_limit_failures": 3,
                "auth_rate_limit_ban_seconds": 60,
            },
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        for i in range(1, 4):
            res = MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                mk,
                identity=210 + i,
                counter=1,
                plaintext_after_prelude=b"\x63" * 64,
                timeout=4.0,
                wait_for_close=True,
            )
            _assert_silent_rst(res, f"bad ClientHello #{i}")

        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                extra={"handshake_timeout_seconds": 2},
                masking={"enabled": True},
            ),
        )
        cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=5.0)
        assert cp.returncode != 0, "4th connection should be rejected by AuthRateLimiter ban"
        rl = srv.wait_for_metric(
            "uncrowned_king_server_rate_limited_connections_total",
            lambda v: v >= 1,
            timeout=3.0,
        )
        assert rl >= 1


# ---------------------------------------------------------------------------
# R2: Unauthenticated Pre-Admission Concurrency Limits (6 tests)
# ---------------------------------------------------------------------------

def t1_r2_01_global_pre_admission_limit_enforced(ctx: TestContext) -> None:
    """Global max_pre_auth_connections=3 holds 3 silent sockets and RST-drops 4th immediately."""
    with ctx.workspace("t1_r2_01") as ws:
        srv, tcp_port, _, _ = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={
                "max_pre_auth_connections": 3,
                "max_pre_auth_per_source": 3,
                "max_handshakes": 64,
                "handshake_timeout_seconds": 5,
            },
        )
        held: List[socket.socket] = []
        try:
            for _ in range(3):
                held.append(MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=2.0))
            for idx, s in enumerate(held):
                assert check_socket_closed(s, timeout=0.05) == CloseKind.OPEN, (
                    f"held socket #{idx + 1} unexpectedly closed"
                )

            s4 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=2.0)
            held.append(s4)
            res4 = read_until_close(s4, timeout=1.5)
            _assert_silent_rst(res4, "4th pre-auth socket over global limit")
            assert res4.elapsed_s < 0.5, (
                f"expected immediate drop (<0.5s), took {res4.elapsed_s:.3f}s"
            )

            for idx in range(3):
                assert check_socket_closed(held[idx], timeout=0.05) == CloseKind.OPEN, (
                    f"held socket #{idx + 1} closed when 4th was dropped"
                )

            pre_rej = _find_pre_admission_reject_metric(srv.get_metrics())
            assert pre_rej is not None and pre_rej >= 1, (
                f"expected pre-admission reject metric >= 1, got {pre_rej}"
            )
        finally:
            _close_all(held)


def t1_r2_02_per_source_ipv4_limit_enforced(ctx: TestContext) -> None:
    """Per-source IPv4 max_pre_auth_per_source=2 holds 2 sockets and RST-drops 3rd."""
    with ctx.workspace("t1_r2_02") as ws:
        _, tcp_port, _, _ = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={
                "max_pre_auth_connections": 16,
                "max_pre_auth_per_source": 2,
                "handshake_timeout_seconds": 5,
            },
        )
        held: List[socket.socket] = []
        try:
            for _ in range(2):
                held.append(MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=2.0))
            for idx, s in enumerate(held):
                assert check_socket_closed(s, timeout=0.05) == CloseKind.OPEN, (
                    f"held IPv4 socket #{idx + 1} closed prematurely"
                )

            s3 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=2.0)
            held.append(s3)
            res3 = read_until_close(s3, timeout=1.5)
            _assert_silent_rst(res3, "3rd IPv4 socket over per-source limit")
            assert res3.elapsed_s < 0.5, (
                f"expected immediate drop (<0.5s), took {res3.elapsed_s:.3f}s"
            )
            for idx in range(2):
                assert check_socket_closed(held[idx], timeout=0.05) == CloseKind.OPEN
        finally:
            _close_all(held)


def t1_r2_03_per_source_ipv6_slash64_limit_enforced(ctx: TestContext) -> None:
    """Per-source IPv6 /64 max_pre_auth_per_source=2 holds 2 ::1 sockets and RST-drops 3rd."""
    sources = discover_loopback_sources()
    assert "::1" in sources, f"expected ::1 loopback source, found {sources}"
    with ctx.workspace("t1_r2_03") as ws:
        _, tcp_port, _, _ = _setup_masked_tcp_server(
            ws,
            ctx,
            listen_host="::",
            limits={
                "max_pre_auth_connections": 16,
                "max_pre_auth_per_source": 2,
                "handshake_timeout_seconds": 5,
            },
        )
        held: List[socket.socket] = []
        try:
            for _ in range(2):
                held.append(
                    MaskedTcpProbe.open_socket("::1", tcp_port, source_addr="::1", timeout=2.0)
                )
            for idx, s in enumerate(held):
                assert check_socket_closed(s, timeout=0.05) == CloseKind.OPEN, (
                    f"held IPv6 socket #{idx + 1} closed prematurely"
                )

            s3 = MaskedTcpProbe.open_socket("::1", tcp_port, source_addr="::1", timeout=2.0)
            held.append(s3)
            res3 = read_until_close(s3, timeout=1.5)
            _assert_silent_rst(res3, "3rd IPv6 ::1 socket over per-source limit")
            assert res3.elapsed_s < 0.5, (
                f"expected immediate IPv6 drop (<0.5s), took {res3.elapsed_s:.3f}s"
            )
        finally:
            _close_all(held)


def t1_r2_04_other_source_succeeds_when_one_source_saturated(ctx: TestContext) -> None:
    """Saturating ::1 per-source limit still allows 127.0.0.1 uk-client HTTP relay."""
    sources = discover_loopback_sources()
    assert "::1" in sources and "127.0.0.1" in sources, (
        f"need both ::1 and 127.0.0.1, got {sources}"
    )
    with ctx.workspace("t1_r2_04") as ws:
        http_srv = ws.enter(LocalHttpServer())
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            listen_host="::",
            limits={
                "max_pre_auth_connections": 8,
                "max_pre_auth_per_source": 2,
                "handshake_timeout_seconds": 5,
            },
            policy_ports=[http_srv.port],
        )
        held: List[socket.socket] = []
        try:
            for _ in range(2):
                held.append(
                    MaskedTcpProbe.open_socket("::1", tcp_port, source_addr="::1", timeout=2.0)
                )
            for s in held:
                assert check_socket_closed(s, timeout=0.05) == CloseKind.OPEN

            socks_port = free_tcp_port("127.0.0.1")
            cli_obs = free_tcp_port("127.0.0.1")
            cli_cfg = ws.write_secret(
                "client.toml",
                build_client_toml(
                    server_addr=f"tls://127.0.0.1:{tcp_port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    observability_listen=f"127.0.0.1:{cli_obs}",
                    masking={"enabled": True},
                ),
            )
            cli = ws.enter(
                UkClientProcess(
                    ctx.client_bin,
                    cli_cfg,
                    f"127.0.0.1:{socks_port}",
                    f"127.0.0.1:{cli_obs}",
                )
            )
            cli.wait_ready(require_session=True, timeout=10.0)
            status, _hdrs, body = Socks5Client.socks5_http_get(
                "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/8192"
            )
            assert status == 200 and body == deterministic_bytes(8192)
            for s in held:
                assert check_socket_closed(s, timeout=0.05) == CloseKind.OPEN
        finally:
            _close_all(held)


def t1_r2_05_pre_auth_slots_released_after_auth_and_close(ctx: TestContext) -> None:
    """Pre-auth slots (limit=2) release upon auth completion and upon connection close."""
    with ctx.workspace("t1_r2_05") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={
                "max_pre_auth_connections": 2,
                "max_pre_auth_per_source": 2,
                "handshake_timeout_seconds": 5,
            },
        )
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                extra={"max_carrier_sessions": 1},
                masking={"enabled": True},
            ),
        )
        # Hold 2 authenticated sessions simultaneously, then prove a 3rd client can
        # still authenticate (pre-auth slots were released after authentication).
        live_clients: List[UkClientProcess] = []
        try:
            for idx in range(2):
                sp = free_tcp_port("127.0.0.1")
                co = free_tcp_port("127.0.0.1")
                c_toml = ws.write_secret(
                    f"client_{idx}.toml",
                    build_client_toml(
                        server_addr=f"tls://127.0.0.1:{tcp_port}",
                        ca_cert_path=ws.path / "server-ca-cert.pem",
                        key_id=str(creds[0]["key_id"]),
                        secret=str(creds[0]["secret"]),
                        observability_listen=f"127.0.0.1:{co}",
                        extra={"max_carrier_sessions": 1},
                        masking={"enabled": True},
                    ),
                )
                c = UkClientProcess(ctx.client_bin, c_toml, f"127.0.0.1:{sp}", f"127.0.0.1:{co}")
                live_clients.append(c)
                c.wait_ready(require_session=True, timeout=10.0)

            cp_during = run_client_handshake(ctx.client_bin, cli_cfg)
            assert cp_during.returncode == 0, (
                f"3rd handshake failed while 2 authenticated sessions open: {cp_during.stderr}"
            )
        finally:
            for c in live_clients:
                c.stop()

        for i in range(4):
            cp = run_client_handshake(ctx.client_bin, cli_cfg)
            assert cp.returncode == 0, (
                f"sequential handshake #{i + 3} failed: {cp.stdout}\n{cp.stderr}"
            )


def t1_r2_06_pre_admission_active_on_unmasked_tcp_too(ctx: TestContext) -> None:
    """Unmasked TCP server enforces max_pre_auth_per_source=2 and drops 3rd with RST."""
    with ctx.workspace("t1_r2_06") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]
        tcp_port = free_tcp_port("127.0.0.1")
        obs_port = free_tcp_port("127.0.0.1")
        pol_path = ws.write_secret("policy.toml", allow_loopback_policy())
        srv_cfg = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                observability_listen=f"127.0.0.1:{obs_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=pol_path,
                credentials=creds,
                limits={
                    "max_pre_auth_connections": 16,
                    "max_pre_auth_per_source": 2,
                    "handshake_timeout_seconds": 5,
                },
                masking=None,
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_cfg, f"127.0.0.1:{obs_port}")
        )
        srv.wait_ready()

        held: List[socket.socket] = []
        try:
            for _ in range(2):
                held.append(MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=2.0))
            for s in held:
                assert check_socket_closed(s, timeout=0.05) == CloseKind.OPEN

            s3 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=2.0)
            held.append(s3)
            res3 = read_until_close(s3, timeout=1.5)
            _assert_silent_rst(res3, "3rd unmasked pre-auth socket")
            assert res3.elapsed_s < 0.5, (
                f"expected immediate unmasked drop (<0.5s), took {res3.elapsed_s:.3f}s"
            )
        finally:
            _close_all(held)


# ---------------------------------------------------------------------------
# R3: Masked QUIC max_udp_payload_size - 12, Poll::Pending, incoming.ignore()
# ---------------------------------------------------------------------------

def t1_r3_01_masked_quic_full_socks5_relay(ctx: TestContext) -> None:
    """Masked QUIC server + client relays 128 KiB HTTP payload via curl --socks5-hostname."""
    with ctx.workspace("t1_r3_01") as ws:
        http_srv = ws.enter(LocalHttpServer())
        quic_port = free_udp_port("127.0.0.1")
        _, _, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            quic_port=quic_port,
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
            policy_ports=[http_srv.port],
        )
        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{quic_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                masking={"enabled": True, "quic": True},
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin, cli_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
            )
        )
        cli.wait_ready(require_session=True, timeout=12.0)

        expected = deterministic_bytes(131072)
        expected_sha = hashlib.sha256(expected).hexdigest()
        curl_bin = shutil.which("curl")
        if curl_bin:
            proc = subprocess.run(
                [
                    curl_bin,
                    "-fsS",
                    "--socks5-hostname",
                    f"127.0.0.1:{socks_port}",
                    f"http://127.0.0.1:{http_srv.port}/bytes/131072",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20.0,
                check=False,
            )
            assert proc.returncode == 0, f"curl failed: {proc.stderr.decode('utf-8', 'replace')}"
            got_sha = hashlib.sha256(proc.stdout).hexdigest()
            assert got_sha == expected_sha, f"SHA-256 mismatch: {got_sha} != {expected_sha}"
        else:
            status, _hdrs, body = Socks5Client.socks5_http_get(
                "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/131072"
            )
            assert status == 200 and hashlib.sha256(body).hexdigest() == expected_sha


def t1_r3_02_masked_quic_large_payload_mtu_1440(ctx: TestContext) -> None:
    """Masked QUIC relays 2 MiB TCP stream and near-MTU (1100-1350B) UDP datagrams within 1452B/1472B wire cap."""
    with ctx.workspace("t1_r3_02") as ws:
        tcp_echo = ws.enter(LocalTcpEchoServer())
        udp_echo = ws.enter(LocalUdpEchoServer())
        quic_port = free_udp_port("127.0.0.1")
        _, _, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            quic_port=quic_port,
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
            policy_ports=[tcp_echo.port, udp_echo.port],
        )
        # masked_endpoint_config() max_udp_payload_size = 1460 (+12B nonce = 1472B wire);
        # apply_masked_mtu() discovery upper_bound = 1440 (+12B nonce = 1452B wire).
        masked_max_wire_size = 1452
        proxy = ws.enter(UdpObserverProxy("127.0.0.1", quic_port))
        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{proxy.port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                masking={"enabled": True, "quic": True},
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin, cli_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
            )
        )
        cli.wait_ready(require_session=True, timeout=12.0)

        tcp_payload = deterministic_bytes(2 * 1024 * 1024, seed=0x5233)
        echoed_tcp = Socks5Client.socks5_echo(
            "127.0.0.1", socks_port, "127.0.0.1", tcp_echo.port, tcp_payload, timeout=30.0
        )
        assert hashlib.sha256(echoed_tcp).hexdigest() == hashlib.sha256(tcp_payload).hexdigest()

        udp_payloads = [
            deterministic_bytes(1100, seed=1),
            deterministic_bytes(1250, seed=2),
            deterministic_bytes(1350, seed=3),
        ]
        echoed_udp = Socks5Client.socks5_udp_exchange(
            "127.0.0.1", socks_port, "127.0.0.1", udp_echo.port, udp_payloads, timeout=15.0
        )
        assert echoed_udp == udp_payloads

        c2s_pkts, s2c_pkts = proxy.snapshot()
        all_pkts = c2s_pkts + s2c_pkts
        assert len(all_pkts) > 0, "expected captured masked QUIC wire datagrams"
        oversized = [len(p) for p in all_pkts if len(p) > masked_max_wire_size]
        assert not oversized, (
            f"masked QUIC wire datagrams exceeded {masked_max_wire_size}B "
            f"(apply_masked_mtu 1440+12): max={max(oversized)}"
        )


def t1_r3_03_masked_quic_invalid_udp_batch_no_starvation(ctx: TestContext) -> None:
    """2,000 invalid/short/wrong-key/v0 UDP datagrams produce 0 replies without starving QUIC relay or /metrics."""
    with ctx.workspace("t1_r3_03") as ws:
        http_srv = ws.enter(LocalHttpServer())
        quic_port = free_udp_port("127.0.0.1")
        _, _, obs_port, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            quic_port=quic_port,
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
            policy_ports=[http_srv.port],
        )
        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{quic_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                masking={"enabled": True, "quic": True},
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin, cli_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
            )
        )
        cli.wait_ready(require_session=True, timeout=12.0)

        right_keys = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        wrong_keys = derive_mask_keys("wrong", make_secret())
        v0_masked = build_quic_initial_probe(version=0, size=120)
        wrong_masked = build_quic_initial_probe(version=1, size=120)

        probe_replies: List[bytes] = []
        flood_errors: List[Exception] = []

        def _flood() -> None:
            try:
                with QuicProbeSocket("127.0.0.1", quic_port) as qp:
                    for i in range(2000):
                        mode = i % 5
                        if mode == 0:
                            qp.send_raw(b"")
                        elif mode == 1:
                            qp.send_raw(b"\x01\x02\x03")
                        elif mode == 2:
                            qp.send_raw(os.urandom(12))
                        elif mode == 3:
                            qp.send_masked(wrong_keys, wrong_masked)
                        else:
                            qp.send_masked(right_keys, v0_masked)
                    probe_replies.extend(qp.recv_packets(timeout=0.5))
            except Exception as exc:  # pragma: no cover - surfaced below
                flood_errors.append(exc)

        flood_thread = threading.Thread(target=_flood, daemon=True)
        flood_thread.start()

        expected = deterministic_bytes(16384)
        for idx in range(5):
            st, _h, body = Socks5Client.socks5_http_get(
                "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/16384", timeout=10.0
            )
            assert st == 200 and body == expected, f"HTTP transfer #{idx + 1} failed during flood"
            m_st, _ = http_get("127.0.0.1", port=obs_port, path="/metrics", timeout=1.5)
            assert m_st == 200, f"/metrics returned {m_st} during flood"

        flood_thread.join(timeout=15.0)
        assert not flood_thread.is_alive(), "UDP flood thread did not finish"
        assert not flood_errors, f"UDP flood error: {flood_errors}"
        assert probe_replies == [], f"expected 0 UDP replies to invalid flood, got {len(probe_replies)}"


def t1_r3_04_masked_quic_rate_limit_emits_zero_packets(ctx: TestContext) -> None:
    """Rate-limited masked QUIC peer receives 0 non-Retry packets (incoming.ignore())."""
    with ctx.workspace("t1_r3_04") as ws:
        quic_port = free_udp_port("127.0.0.1")
        srv, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            quic_port=quic_port,
            limits={
                "auth_rate_limit_failures": 1,
                "auth_rate_limit_ban_seconds": 60,
                "handshake_timeout_seconds": 2,
            },
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        # Trigger IP ban on 127.0.0.1 via invalid TCP prelude.
        res = MaskedTcpProbe.send_and_probe("127.0.0.1", tcp_port, b"\x00" * 76, timeout=4.0)
        _assert_silent_rst(res, "ban-trigger prelude")
        srv.wait_for_metric("uncrowned_king_server_mask_prelude_rejects_total", lambda v: v >= 1)

        with UdpObserverProxy("127.0.0.1", quic_port) as proxy:
            cli_cfg = ws.write_secret(
                "client_rl.toml",
                build_client_toml(
                    server_addr=f"quic://127.0.0.1:{proxy.port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    extra={"handshake_timeout_seconds": 1},
                    masking={"enabled": True, "quic": True},
                ),
            )
            cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=5.0)
            assert cp.returncode != 0, "banned QUIC client should fail handshake"
            srv.wait_for_metric(
                "uncrowned_king_server_rate_limited_connections_total",
                lambda v: v >= 1,
                timeout=3.0,
            )
            non_retry = proxy.non_retry_s2c_packets(mk)
            assert non_retry == [], (
                f"expected 0 non-Retry UDP response packets (incoming.ignore()), got {len(non_retry)}: "
                f"{[p[:8].hex() for p in non_retry]}"
            )


def t1_r3_05_masked_quic_permit_exhaustion_emits_zero_packets(ctx: TestContext) -> None:
    """Permit-exhausted masked QUIC server sends 0 non-Retry packets and preserves active session."""
    with ctx.workspace("t1_r3_05") as ws:
        http_srv = ws.enter(LocalHttpServer())
        quic_port = free_udp_port("127.0.0.1")
        srv, _, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            quic_port=quic_port,
            limits={"max_sessions": 1, "handshake_timeout_seconds": 2},
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
            policy_ports=[http_srv.port],
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])

        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli1_cfg = ws.write_secret(
            "client1.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{quic_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                extra={"max_carrier_sessions": 1},
                masking={"enabled": True, "quic": True},
            ),
        )
        cli1 = ws.enter(
            UkClientProcess(
                ctx.client_bin, cli1_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
            )
        )
        cli1.wait_ready(require_session=True, timeout=12.0)

        with UdpObserverProxy("127.0.0.1", quic_port) as proxy:
            cli2_cfg = ws.write_secret(
                "client2.toml",
                build_client_toml(
                    server_addr=f"quic://127.0.0.1:{proxy.port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    extra={"handshake_timeout_seconds": 1},
                    masking={"enabled": True, "quic": True},
                ),
            )
            cp2 = run_client_handshake(ctx.client_bin, cli2_cfg, timeout=5.0)
            assert cp2.returncode != 0, "2nd QUIC client should fail when max_sessions=1"
            srv.wait_for_metric(
                "uncrowned_king_server_rejected_sessions_total",
                lambda v: v >= 1,
                timeout=3.0,
            )
            non_retry = proxy.non_retry_s2c_packets(mk)
            assert non_retry == [], (
                f"expected 0 non-Retry UDP packets on permit exhaustion, got {len(non_retry)}"
            )

        st, _h, body = Socks5Client.socks5_http_get(
            "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/8192"
        )
        assert st == 200 and body == deterministic_bytes(8192)


def t1_r3_06_masked_quic_wrong_key_id_fails_silently(ctx: TestContext) -> None:
    """uk-client using wrong credential key_id over masked QUIC receives 0 UDP packets and fails."""
    with ctx.workspace("t1_r3_06") as ws:
        quic_port = free_udp_port("127.0.0.1")
        creds = [
            {"key_id": "k1", "secret": make_secret()},
            {"key_id": "k2", "secret": make_secret()},
        ]
        _setup_masked_tcp_server(
            ws,
            ctx,
            quic_port=quic_port,
            credentials=creds,
            limits={"handshake_timeout_seconds": 2},
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
        )
        with UdpObserverProxy("127.0.0.1", quic_port) as proxy:
            cli_cfg = ws.write_secret(
                "client_wrong.toml",
                build_client_toml(
                    server_addr=f"quic://127.0.0.1:{proxy.port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id="k2",
                    secret=str(creds[1]["secret"]),
                    extra={"handshake_timeout_seconds": 1},
                    masking={"enabled": True, "quic": True},
                ),
            )
            cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=5.0)
            assert cp.returncode != 0, "masked QUIC client with wrong key_id must fail"
            assert len(proxy.c2s) >= 1, "client should have transmitted UDP datagrams"
            assert proxy.s2c == [], (
                f"expected 0 UDP responses for wrong QUIC key_id, got {len(proxy.s2c)}"
            )


# ---------------------------------------------------------------------------
# R4: Full-Handshake SO_LINGER=0 & Single Shared Absolute Deadline (6 tests)
# ---------------------------------------------------------------------------

def t1_r4_01_single_shared_deadline_across_phases(ctx: TestContext) -> None:
    """1.5s Phase 1 delay + stalled Phase 2 closes with RST at ~3.0s total (shared deadline)."""
    with ctx.workspace("t1_r4_01") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 3, "auth_rate_limit_failures": 10},
        )
        with StallProxy(
            "127.0.0.1", tcp_port, phase1_delay_s=1.5, hold_phase2=True
        ) as proxy:
            cli_cfg = ws.write_secret(
                "client.toml",
                build_client_toml(
                    server_addr=f"tls://127.0.0.1:{proxy.listen_port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    extra={"handshake_timeout_seconds": 10},
                    masking={"enabled": True},
                ),
            )
            result_box: List[subprocess.CompletedProcess] = []
            t = threading.Thread(
                target=lambda: result_box.append(
                    run_client_handshake(ctx.client_bin, cli_cfg, timeout=12.0)
                ),
                daemon=True,
            )
            t.start()
            rec = proxy.wait_for_session_close(index=0, timeout=10.0)
            t.join(timeout=10.0)
            assert rec.server_first_reply_at is not None, "server never replied after Phase 1"
            assert rec.phase2_received_at is not None, "client never sent Phase 2 AuthResponse"
            assert rec.server_close_kind == CloseKind.RST, (
                f"expected RST on shared-deadline timeout, got {rec.server_close_kind}"
            )
            assert rec.elapsed_s is not None and 2.2 <= rec.elapsed_s <= 4.2, (
                f"expected single ~3.0s shared deadline ([2.2, 4.2]), got {rec.elapsed_s}"
            )


def t1_r4_02_pre_auth_tls_failure_closes_with_rst(ctx: TestContext) -> None:
    """Post-ClientHello TLS failure before auth completion closes via RST (SO_LINGER=0)."""
    with ctx.workspace("t1_r4_02") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 3, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        prelude, nonce = encode_prelude(mk, identity=402, counter=1)
        c2s = ChaCha20Stream(mk.tcp_c2s, nonce)
        s2c = ChaCha20Stream(mk.tcp_s2c, nonce)
        sock = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=4.0)
        try:
            sock.sendall(prelude + c2s.apply(build_tls13_client_hello()))
            first = read_first_response(sock, timeout=3.0, decrypt_stream=s2c)
            _assert_server_hello(first, "pre-auth TLS ServerHello")
            sock.sendall(c2s.apply(b"\x16\x03\x03\x00\x05\xff\xff\xff\xff\xff"))
            tail = read_until_close(sock, timeout=4.0, decrypt_stream=s2c)
            assert tail.close_kind == CloseKind.RST, (
                f"expected RST on post-ClientHello pre-auth TLS failure, got {tail.close_kind}"
            )
        finally:
            sock.close()


def t1_r4_03_post_auth_normal_close_uses_fin(ctx: TestContext) -> None:
    """Post-auth session restores normal linger so graceful SIGTERM drain completes cleanly via FIN."""
    with ctx.workspace("t1_r4_03") as ws:
        http_srv = ws.enter(LocalHttpServer())
        srv, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 5, "shutdown_timeout_seconds": 8},
            policy_ports=[http_srv.port],
        )
        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                masking={"enabled": True},
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin, cli_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
            )
        )
        cli.wait_ready(require_session=True, timeout=10.0)

        out: List[Tuple[int, bytes]] = []
        err: List[Exception] = []

        def _slow_get() -> None:
            try:
                st, _h, body = Socks5Client.socks5_http_get(
                    "127.0.0.1",
                    socks_port,
                    "127.0.0.1",
                    http_srv.port,
                    "/slow?bytes=65536&chunk=8192&delay_ms=25",
                    timeout=15.0,
                )
                out.append((st, body))
            except Exception as exc:  # pragma: no cover
                err.append(exc)

        t = threading.Thread(target=_slow_get, daemon=True)
        t.start()
        srv.wait_for_metric(
            "uncrowned_king_server_opened_flows_total",
            lambda v: v >= 1,
            labels={"protocol": "tcp"},
            timeout=5.0,
        )
        srv.send_sigterm()
        t.join(timeout=15.0)
        assert not t.is_alive(), "slow GET did not finish"
        assert not err, f"transfer aborted instead of graceful FIN drain: {err}"
        assert out and out[0][0] == 200 and out[0][1] == deterministic_bytes(65536), (
            "active masked HTTP transfer did not complete intact across graceful drain"
        )
        rc = srv.wait_exit(timeout=10.0)
        assert rc == 0, f"server exited with {rc} on graceful SIGTERM"


def t1_r4_04_linger_preserved_across_alpn_mismatch(ctx: TestContext) -> None:
    """Wrong ALPN ('h2') after valid prelude + TLS 1.3 ClientHello closes via RST."""
    with ctx.workspace("t1_r4_04") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 3, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        res = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=404,
            counter=1,
            plaintext_after_prelude=build_tls13_client_hello(alpn=b"h2"),
            timeout=5.0,
            wait_for_close=True,
        )
        assert res.close_kind == CloseKind.RST, (
            f"expected RST on ALPN mismatch (SO_LINGER=0 preserved), got {res.close_kind}"
        )


def t1_r4_05_prelude_timeout_closes_with_rst(ctx: TestContext) -> None:
    """Silent TCP connection sending 0 bytes times out at deadline and closes via RST."""
    with ctx.workspace("t1_r4_05") as ws:
        _, tcp_port, _, _ = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        sock = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=5.0)
        try:
            res = read_until_close(sock, timeout=6.0)
            _assert_silent_rst(res, "0-byte prelude timeout")
            assert 1.5 <= res.elapsed_s <= 4.0, (
                f"expected timeout close in [1.5s, 4.0s], got {res.elapsed_s:.3f}s"
            )
        finally:
            sock.close()


def t1_r4_06_auth_timeout_after_fast_tls_closes_with_rst(ctx: TestContext) -> None:
    """Fast TLS + stalled AuthResponse times out at handshake_timeout=2s with RST."""
    with ctx.workspace("t1_r4_06") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        with StallProxy(
            "127.0.0.1", tcp_port, phase1_delay_s=0.0, hold_phase2=True
        ) as proxy:
            cli_cfg = ws.write_secret(
                "client.toml",
                build_client_toml(
                    server_addr=f"tls://127.0.0.1:{proxy.listen_port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    extra={"handshake_timeout_seconds": 10},
                    masking={"enabled": True},
                ),
            )
            t = threading.Thread(
                target=lambda: run_client_handshake(ctx.client_bin, cli_cfg, timeout=10.0),
                daemon=True,
            )
            t.start()
            rec = proxy.wait_for_session_close(index=0, timeout=8.0)
            t.join(timeout=8.0)
            assert rec.server_first_reply_at is not None
            assert rec.phase2_received_at is not None
            assert rec.server_close_kind == CloseKind.RST, (
                f"expected RST on AuthResponse timeout, got {rec.server_close_kind}"
            )
            assert rec.elapsed_s is not None and 1.5 <= rec.elapsed_s <= 3.2, (
                f"expected ~2s auth timeout ([1.5, 3.2]), got {rec.elapsed_s}"
            )


# ---------------------------------------------------------------------------
# R5: Zero-Alloc ReplayRegistry, Hot-Path & Client 76B Coalescing (6 tests)
# ---------------------------------------------------------------------------

def t1_r5_01_client_76b_coalesced_first_segment(ctx: TestContext) -> None:
    """Client MaskedStream coalesces 76B prelude + encrypted ClientHello into first TCP send."""
    with ctx.workspace("t1_r5_01") as ws:
        _, tcp_port, _, creds = _setup_masked_tcp_server(ws, ctx)
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        with TransparentFirstSegmentProxy("127.0.0.1", tcp_port) as proxy:
            cli_cfg = ws.write_secret(
                "client.toml",
                build_client_toml(
                    server_addr=f"tls://127.0.0.1:{proxy.listen_port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    masking={"enabled": True, "prelude_policy": "fade"},
                ),
            )
            cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=10.0)
            assert cp.returncode == 0, f"client handshake failed: {cp.stderr}"
            seg = proxy.wait_for_first_segment(timeout=5.0)
            assert len(seg) >= WIRE_PRELUDE_LEN + 5, (
                f"expected coalesced first segment >= {WIRE_PRELUDE_LEN + 5}B, got {len(seg)}B"
            )
            nonce = seg[64:76]
            dec = ChaCha20Stream(mk.tcp_c2s, nonce).apply(seg[76:])
            assert dec[0] == 0x16 and dec[5] == 0x01, (
                f"coalesced tail did not decrypt to TLS ClientHello: {dec[:12].hex()}"
            )


def t1_r5_02_client_coalescing_all_prelude_policies(ctx: TestContext) -> None:
    """76B coalescing + full HTTP relay work across fade, full8, and low7 prelude policies."""
    with ctx.workspace("t1_r5_02") as ws:
        http_srv = ws.enter(LocalHttpServer())
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws, ctx, policy_ports=[http_srv.port]
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        expected = deterministic_bytes(32768)

        for policy in ("fade", "full8", "low7"):
            with TransparentFirstSegmentProxy("127.0.0.1", tcp_port) as proxy:
                socks_port = free_tcp_port("127.0.0.1")
                cli_obs = free_tcp_port("127.0.0.1")
                cli_cfg = ws.write_secret(
                    f"client_{policy}.toml",
                    build_client_toml(
                        server_addr=f"tls://127.0.0.1:{proxy.listen_port}",
                        ca_cert_path=ws.path / "server-ca-cert.pem",
                        key_id=str(creds[0]["key_id"]),
                        secret=str(creds[0]["secret"]),
                        observability_listen=f"127.0.0.1:{cli_obs}",
                        extra={"max_carrier_sessions": 1},
                        masking={"enabled": True, "prelude_policy": policy},
                    ),
                )
                with UkClientProcess(
                    ctx.client_bin,
                    cli_cfg,
                    f"127.0.0.1:{socks_port}",
                    f"127.0.0.1:{cli_obs}",
                ) as cli:
                    cli.wait_ready(require_session=True, timeout=10.0)
                    seg = proxy.wait_for_first_segment(timeout=5.0)
                    assert len(seg) >= WIRE_PRELUDE_LEN + 5, (
                        f"policy={policy}: expected coalesced >= 81B, got {len(seg)}B"
                    )
                    dec = ChaCha20Stream(mk.tcp_c2s, seg[64:76]).apply(seg[76:])
                    assert dec[0] == 0x16 and dec[5] == 0x01, (
                        f"policy={policy}: coalesced bytes not TLS ClientHello"
                    )
                    st, _h, body = Socks5Client.socks5_http_get(
                        "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/32768"
                    )
                    assert st == 200 and body == expected


def t1_r5_03_masked_stream_large_payload_over_64kib(ctx: TestContext) -> None:
    """Masked TCP GET and POST of 512 KiB (> MAX_WRITE_CHUNK 64 KiB) achieve SHA-256 parity."""
    with ctx.workspace("t1_r5_03") as ws:
        http_srv = ws.enter(LocalHttpServer())
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws, ctx, policy_ports=[http_srv.port]
        )
        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                masking={"enabled": True},
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin, cli_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
            )
        )
        cli.wait_ready(require_session=True, timeout=10.0)

        expected_get = deterministic_bytes(524288)
        st, _h, got_get = Socks5Client.socks5_http_get(
            "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/524288", timeout=20.0
        )
        assert st == 200 and hashlib.sha256(got_get).hexdigest() == hashlib.sha256(expected_get).hexdigest()

        post_data = deterministic_bytes(524288, seed=0xCAFE)
        st_p, _h_p, got_post = Socks5Client.socks5_http_post(
            "127.0.0.1",
            socks_port,
            "127.0.0.1",
            http_srv.port,
            "/echo",
            body=post_data,
            timeout=20.0,
        )
        assert st_p == 200 and hashlib.sha256(got_post).hexdigest() == hashlib.sha256(post_data).hexdigest()


def t1_r5_04_replay_registry_eviction_at_min_capacity(ctx: TestContext) -> None:
    """ReplayRegistry (capacity=1024) evicts oldest identity #1 in FIFO order after 1025 inserts."""
    with ctx.workspace("t1_r5_04") as ws:
        srv, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"auth_rate_limit_failures": 0, "handshake_timeout_seconds": 5},
            masking={"enabled": True, "replay_identities": 1024},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        hello = build_tls13_client_hello()

        def _send_one(ident: int) -> None:
            res = MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                mk,
                identity=ident,
                counter=1,
                plaintext_after_prelude=hello,
                timeout=8.0,
                wait_for_close=False,
            )
            _assert_server_hello(res, f"identity={ident}")

        # Commit identity 1 first so it is strictly oldest in the 1024-slot FIFO ring.
        _send_one(1)

        # Commit identities 2..1024 concurrently with bounded concurrency <= 16
        # (well below default max_pre_auth_per_source = 32).
        with ThreadPoolExecutor(max_workers=16) as pool:
            futs = [pool.submit(_send_one, ident) for ident in range(2, 1025)]
            for fut in futs:
                fut.result()

        # Commit identity 1025 last so identity 1 is evicted.
        _send_one(1025)

        # Identity 1 was evicted and must now be accepted again.
        res_evicted = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=1,
            counter=1,
            plaintext_after_prelude=hello,
            timeout=5.0,
            wait_for_close=False,
        )
        _assert_server_hello(res_evicted, "evicted identity=1 re-accepted")

        # Identity 1025 is still in the ring and must be rejected as replay.
        res_dup = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=1025,
            counter=1,
            plaintext_after_prelude=hello,
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res_dup, "retained identity=1025 rejected as replay")
        replays = srv.wait_for_metric(
            "uncrowned_king_server_mask_replay_rejects_total",
            lambda v: v >= 1,
            timeout=3.0,
        )
        assert replays >= 1


def t1_r5_05_replay_window_out_of_order_and_duplicate(ctx: TestContext) -> None:
    """Out-of-order ctr=5 after ctr=10 succeeds; duplicate ctr=10 and ctr=5 are rejected."""
    with ctx.workspace("t1_r5_05") as ws:
        srv, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        hello = build_tls13_client_hello()

        for ctr in (10, 5):
            r = MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                mk,
                identity=777,
                counter=ctr,
                plaintext_after_prelude=hello,
                timeout=5.0,
                wait_for_close=False,
            )
            _assert_server_hello(r, f"fresh counter={ctr}")

        for ctr in (10, 5):
            r_dup = MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                mk,
                identity=777,
                counter=ctr,
                plaintext_after_prelude=hello,
                timeout=5.0,
                wait_for_close=True,
            )
            _assert_silent_rst(r_dup, f"duplicate counter={ctr}")

        replays = srv.wait_for_metric(
            "uncrowned_king_server_mask_replay_rejects_total",
            lambda v: v >= 2,
            timeout=3.0,
        )
        assert replays == 2, f"expected 2 replay rejections, got {replays}"


def t1_r5_06_multi_credential_hoisted_verify(ctx: TestContext) -> None:
    """Server with 5 credentials (k1..k5) authenticates masked clients using k1, k3, k5."""
    with ctx.workspace("t1_r5_06") as ws:
        creds = [{"key_id": f"k{i}", "secret": make_secret()} for i in range(1, 6)]
        _, tcp_port, _, _ = _setup_masked_tcp_server(
            ws, ctx, credentials=creds
        )
        for idx in (0, 2, 4):
            c = creds[idx]
            cli_cfg = ws.write_secret(
                f"client_{c['key_id']}.toml",
                build_client_toml(
                    server_addr=f"tls://127.0.0.1:{tcp_port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(c["key_id"]),
                    secret=str(c["secret"]),
                    masking={"enabled": True},
                ),
            )
            cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=10.0)
            assert cp.returncode == 0, f"handshake with {c['key_id']} failed: {cp.stderr}"


# ---------------------------------------------------------------------------
# R6: Config Bug Fixes & Preserved UK Advantages (6 tests)
# ---------------------------------------------------------------------------

def t1_r6_01_empty_masking_table_allows_unmasked_tcp(ctx: TestContext) -> None:
    """Empty [masking] table (examples/server.toml pattern) accepts unmasked tls:// TCP relay."""
    with ctx.workspace("t1_r6_01") as ws:
        http_srv = ws.enter(LocalHttpServer())
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            masking={},
            policy_ports=[http_srv.port],
        )
        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                masking=None,
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin, cli_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
            )
        )
        cli.wait_ready(require_session=True, timeout=10.0)
        st, _h, body = Socks5Client.socks5_http_get(
            "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/65536"
        )
        assert st == 200 and body == deterministic_bytes(65536)


def t1_r6_02_tcp_disabled_quic_enabled_split_mode(ctx: TestContext) -> None:
    """masking.enabled=false, masking.quic=true allows unmasked TCP & masked QUIC, rejects masked TCP."""
    with ctx.workspace("t1_r6_02") as ws:
        http_srv = ws.enter(LocalHttpServer())
        quic_port = free_udp_port("127.0.0.1")
        _, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            quic_port=quic_port,
            masking={"enabled": False, "quic": True, "quic_key_id": "k1"},
            policy_ports=[http_srv.port],
        )

        # 1. Unmasked TCP client succeeds + relays HTTP.
        socks_tcp = free_tcp_port("127.0.0.1")
        obs_tcp = free_tcp_port("127.0.0.1")
        cfg_tcp = ws.write_secret(
            "client_tcp.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{obs_tcp}",
                masking={"enabled": False, "quic": False},
            ),
        )
        with UkClientProcess(
            ctx.client_bin, cfg_tcp, f"127.0.0.1:{socks_tcp}", f"127.0.0.1:{obs_tcp}"
        ) as c1:
            c1.wait_ready(require_session=True, timeout=10.0)
            st, _h, body = Socks5Client.socks5_http_get(
                "127.0.0.1", socks_tcp, "127.0.0.1", http_srv.port, "/bytes/16384"
            )
            assert st == 200 and body == deterministic_bytes(16384)

        # 2. Masked QUIC client succeeds + relays HTTP.
        socks_quic = free_tcp_port("127.0.0.1")
        obs_quic = free_tcp_port("127.0.0.1")
        cfg_quic = ws.write_secret(
            "client_quic.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{quic_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{obs_quic}",
                masking={"enabled": False, "quic": True},
            ),
        )
        with UkClientProcess(
            ctx.client_bin, cfg_quic, f"127.0.0.1:{socks_quic}", f"127.0.0.1:{obs_quic}"
        ) as c2:
            c2.wait_ready(require_session=True, timeout=12.0)
            st, _h, body = Socks5Client.socks5_http_get(
                "127.0.0.1", socks_quic, "127.0.0.1", http_srv.port, "/bytes/16384"
            )
            assert st == 200 and body == deterministic_bytes(16384)

        # 3. Masked TCP client fails closed against the unmasked TCP listener.
        cfg_bad = ws.write_secret(
            "client_masked_tcp.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                extra={"handshake_timeout_seconds": 2},
                masking={"enabled": True},
            ),
        )
        cp_bad = run_client_handshake(ctx.client_bin, cfg_bad, timeout=6.0)
        assert cp_bad.returncode != 0, (
            "masked TCP client unexpectedly succeeded against TCP-unmasked server"
        )


def t1_r6_03_zero_handshake_timeout_with_masking_fallback(ctx: TestContext) -> None:
    """handshake_timeout_seconds=0 with masking.enabled=true uses non-zero fallback dwell and allows valid clients."""
    with ctx.workspace("t1_r6_03") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]
        tcp_port = free_tcp_port("127.0.0.1")
        obs_port = free_tcp_port("127.0.0.1")
        pol_path = ws.write_secret("policy.toml", allow_loopback_policy())
        srv_cfg = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                observability_listen=f"127.0.0.1:{obs_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=pol_path,
                credentials=creds,
                limits={"handshake_timeout_seconds": 0, "auth_rate_limit_failures": 10},
                masking={"enabled": True},
            ),
        )
        cc = run_config_check(ctx.server_bin, srv_cfg)
        assert cc.returncode == 0, f"config-check rejected timeout=0: {cc.stderr}"

        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_cfg, f"127.0.0.1:{obs_port}")
        )
        srv.wait_ready()

        # Verify warning logged about zero handshake_timeout with masking.
        warn_lines = srv.find_log_messages("handshake_timeout")
        assert warn_lines, (
            f"expected warning mentioning handshake_timeout fallback in logs:\n{srv.logs_text()}"
        )

        # Valid masked uk-client must connect cleanly.
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=str(creds[0]["secret"]),
                masking={"enabled": True},
            ),
        )
        cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=10.0)
        assert cp.returncode == 0, f"valid client failed under timeout=0 fallback: {cp.stderr}"

        # 20B short prelude must NOT time out immediately (fallback ~10s => dwell >= 3.5s).
        res = MaskedTcpProbe.send_and_probe(
            "127.0.0.1", tcp_port, os.urandom(20), timeout=14.0, wait_for_close=True
        )
        _assert_silent_rst(res, "20B short prelude with handshake_timeout_seconds=0")
        assert res.elapsed_s >= 3.5, (
            f"expected non-zero fallback dwell (>= 3.5s), got {res.elapsed_s:.3f}s"
        )


def t1_r6_04_helm_config_check_passes(ctx: TestContext) -> None:
    """./scripts/helm-config-check.sh <bin_dir> passes with exit code 0."""
    script = ctx.repo_root / "scripts" / "helm-config-check.sh"
    assert script.is_file(), f"missing {script}"
    proc = subprocess.run(
        [str(script), str(ctx.bin_dir)],
        cwd=str(ctx.repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60.0,
        check=False,
    )
    assert proc.returncode == 0, (
        f"helm-config-check.sh failed (rc={proc.returncode}):\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


def t1_r6_05_global_governor_enhanced_mode_pins_dwell(ctx: TestContext) -> None:
    """Crossing auth_rate_limit_global_failures=5 pins 6th rejection dwell to full timeout (>=1.8s)."""
    with ctx.workspace("t1_r6_05") as ws:
        srv, tcp_port, _, _ = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={
                "auth_rate_limit_failures": 10,
                "auth_rate_limit_global_failures": 5,
                "handshake_timeout_seconds": 2,
            },
        )

        def _bad_prelude() -> ProbeResult:
            return MaskedTcpProbe.send_and_probe(
                "127.0.0.1", tcp_port, os.urandom(76), timeout=5.0, wait_for_close=True
            )

        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = [pool.submit(_bad_prelude) for _ in range(5)]
            for fut in futs:
                _assert_silent_rst(fut.result(), "governor priming bad prelude")

        srv.wait_for_metric(
            "uncrowned_king_server_mask_prelude_rejects_total",
            lambda v: v >= 5,
            timeout=3.0,
        )

        res6 = _bad_prelude()
        _assert_silent_rst(res6, "6th bad prelude in enhanced mode")
        assert res6.elapsed_s >= 1.8, (
            f"expected enhanced-mode dwell pinned to full 2s timeout (>=1.8s), got {res6.elapsed_s:.3f}s"
        )


def t1_r6_06_replay_metric_separated_from_auth_metric(ctx: TestContext) -> None:
    """Invalid prelude and replayed valid-ClientHello prelude increment separate failure buckets."""
    with ctx.workspace("t1_r6_06") as ws:
        srv, tcp_port, _, creds = _setup_masked_tcp_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])

        res_bad = MaskedTcpProbe.send_and_probe(
            "127.0.0.1", tcp_port, os.urandom(76), timeout=5.0, wait_for_close=True
        )
        _assert_silent_rst(res_bad, "invalid prelude")

        hello = build_tls13_client_hello()
        res_ok = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=301,
            counter=1,
            plaintext_after_prelude=hello,
            timeout=5.0,
            wait_for_close=False,
        )
        _assert_server_hello(res_ok, "initial valid prelude + ClientHello")

        res_rep = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=301,
            counter=1,
            plaintext_after_prelude=hello,
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res_rep, "replayed valid prelude + ClientHello")

        assert srv.wait_for_metric(
            "uncrowned_king_server_mask_prelude_rejects_total", lambda v: v >= 1, timeout=3.0
        ) == 1
        assert srv.wait_for_metric(
            "uncrowned_king_server_mask_replay_rejects_total", lambda v: v >= 1, timeout=3.0
        ) == 1
        assert srv.wait_for_metric(
            "uncrowned_king_server_handshake_failures_total",
            lambda v: v >= 1,
            labels={"reason": "auth"},
            timeout=3.0,
        ) == 1
        assert srv.wait_for_metric(
            "uncrowned_king_server_handshake_failures_total",
            lambda v: v >= 1,
            labels={"reason": "replay"},
            timeout=3.0,
        ) == 1


# ---------------------------------------------------------------------------
# Test Discovery
# ---------------------------------------------------------------------------

def collect_tests(ctx: TestContext) -> List[E2ETestCase]:
    del ctx
    specs: List[Tuple[str, object]] = [
        ("R1", t1_r1_01_valid_prelude_corrupt_hello_silent_rst),
        ("R1", t1_r1_02_valid_prelude_tls_alert_swallowed),
        ("R1", t1_r1_03_corrupt_hello_does_not_burn_counter),
        ("R1", t1_r1_04_valid_hello_commits_counter_blocks_replay),
        ("R1", t1_r1_05_oversized_clienthello_over_64kib_rejected),
        ("R1", t1_r1_06_bad_hello_increments_rate_limiter_to_ban),
        ("R2", t1_r2_01_global_pre_admission_limit_enforced),
        ("R2", t1_r2_02_per_source_ipv4_limit_enforced),
        ("R2", t1_r2_03_per_source_ipv6_slash64_limit_enforced),
        ("R2", t1_r2_04_other_source_succeeds_when_one_source_saturated),
        ("R2", t1_r2_05_pre_auth_slots_released_after_auth_and_close),
        ("R2", t1_r2_06_pre_admission_active_on_unmasked_tcp_too),
        ("R3", t1_r3_01_masked_quic_full_socks5_relay),
        ("R3", t1_r3_02_masked_quic_large_payload_mtu_1440),
        ("R3", t1_r3_03_masked_quic_invalid_udp_batch_no_starvation),
        ("R3", t1_r3_04_masked_quic_rate_limit_emits_zero_packets),
        ("R3", t1_r3_05_masked_quic_permit_exhaustion_emits_zero_packets),
        ("R3", t1_r3_06_masked_quic_wrong_key_id_fails_silently),
        ("R4", t1_r4_01_single_shared_deadline_across_phases),
        ("R4", t1_r4_02_pre_auth_tls_failure_closes_with_rst),
        ("R4", t1_r4_03_post_auth_normal_close_uses_fin),
        ("R4", t1_r4_04_linger_preserved_across_alpn_mismatch),
        ("R4", t1_r4_05_prelude_timeout_closes_with_rst),
        ("R4", t1_r4_06_auth_timeout_after_fast_tls_closes_with_rst),
        ("R5", t1_r5_01_client_76b_coalesced_first_segment),
        ("R5", t1_r5_02_client_coalescing_all_prelude_policies),
        ("R5", t1_r5_03_masked_stream_large_payload_over_64kib),
        ("R5", t1_r5_04_replay_registry_eviction_at_min_capacity),
        ("R5", t1_r5_05_replay_window_out_of_order_and_duplicate),
        ("R5", t1_r5_06_multi_credential_hoisted_verify),
        ("R6", t1_r6_01_empty_masking_table_allows_unmasked_tcp),
        ("R6", t1_r6_02_tcp_disabled_quic_enabled_split_mode),
        ("R6", t1_r6_03_zero_handshake_timeout_with_masking_fallback),
        ("R6", t1_r6_04_helm_config_check_passes),
        ("R6", t1_r6_05_global_governor_enhanced_mode_pins_dwell),
        ("R6", t1_r6_06_replay_metric_separated_from_auth_metric),
    ]
    return [
        E2ETestCase(
            name=fn.__name__,
            tier=1,
            fn=fn,
            requirement=req,
            description=(fn.__doc__ or "").splitlines()[0],
        )
        for req, fn in specs
    ]
