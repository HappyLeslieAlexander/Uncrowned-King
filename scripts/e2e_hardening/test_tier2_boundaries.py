"""Tier 2 (Boundary & Corner Case Tests) for Uncrowned King Production Hardening (R1-R6).

32 opaque-box boundary tests (5 each for R1-R5, 7 for R6) exercising
exact protocol/buffer/window/config/SIGHUP/permission limits against real
`uk-server` and `uk-client` binaries.
"""

from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import os
import socket
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
    run_client_handshake,
    run_config_check,
)
from uk_wire import (
    ChaCha20Stream,
    CloseKind,
    MAX_COUNTER,
    MaskedTcpProbe,
    ProbeResult,
    QuicProbeSocket,
    Socks5Client,
    StallProxy,
    TransparentFirstSegmentProxy,
    UdpObserverProxy,
    WIRE_PRELUDE_LEN,
    build_padded_tls13_client_hello,
    build_tls13_client_hello,
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
        f"{prefix}expected decrypted ServerHello (>=6 bytes), got {len(res.received)} "
        f"(raw={len(res.raw_received)}, close={res.close_kind}, err={res.error})"
    )
    assert res.received[0] == 0x16 and res.received[1:3] == b"\x03\x03", (
        f"{prefix}expected TLS Handshake record 16 03 03, got {res.received[:6].hex()}"
    )
    assert res.received[5] == 0x02, (
        f"{prefix}expected TLS ServerHello (0x02), got 0x{res.received[5]:02x}"
    )


def _assert_silent_rst(res: ProbeResult, context: str = "") -> None:
    prefix = f"{context}: " if context else ""
    assert len(res.raw_received) == 0, (
        f"{prefix}expected 0 wire bytes on silent rejection, got {len(res.raw_received)} bytes: "
        f"{res.raw_received[:32].hex()}"
    )
    assert res.close_kind == CloseKind.RST, (
        f"{prefix}expected RST close, got {res.close_kind} (elapsed={res.elapsed_s:.3f}s)"
    )


def _close_all(sockets: List[socket.socket]) -> None:
    for s in sockets:
        try:
            s.close()
        except OSError:
            pass


_DEFAULT_MASKING = object()


def _setup_server(
    ws,
    ctx: TestContext,
    *,
    limits: Optional[Dict[str, object]] = None,
    masking: object = _DEFAULT_MASKING,
    credentials: Optional[List[Dict[str, object]]] = None,
    listen_host: str = "127.0.0.1",
    quic_host: Optional[str] = None,
    quic_port: Optional[int] = None,
    policy_ports: Optional[List[int]] = None,
) -> Tuple[UkServerProcess, int, int, List[Dict[str, object]]]:
    certs = ws.generate_certs()
    if credentials is None:
        credentials = [{"key_id": "k1", "secret": make_secret()}]
    tcp_port = free_tcp_port(listen_host)
    obs_port = free_tcp_port("127.0.0.1")
    pol_path = ws.write_secret("policy.toml", allow_loopback_policy(ports=policy_ports))
    q_host = quic_host or listen_host
    quic_listen = (
        format_host_port(q_host, quic_port) if quic_port is not None else None
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
# R1 Boundaries (5 tests)
# ---------------------------------------------------------------------------

def t2_r1_01_clienthello_exact_64kib_vs_64kib_plus_1(ctx: TestContext) -> None:
    """65535B ClientHello (rustls MAX_HANDSHAKE_SIZE) succeeds; 65536B and 65537B are silently rejected (0B, RST)."""
    with ctx.workspace("t2_r1_01") as ws:
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 3, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])

        hello_ok = build_padded_tls13_client_hello(65535)
        assert len(hello_ok) == 65535
        res_ok = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=101,
            counter=1,
            plaintext_after_prelude=hello_ok,
            timeout=6.0,
            wait_for_close=False,
        )
        _assert_server_hello(res_ok, "65535B (rustls MAX_HANDSHAKE_SIZE) ClientHello")

        hello_64kib = build_padded_tls13_client_hello(65536)
        assert len(hello_64kib) == 65536
        res_64kib = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=102,
            counter=1,
            plaintext_after_prelude=hello_64kib,
            timeout=6.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res_64kib, "65536B ClientHello (> rustls MAX_HANDSHAKE_SIZE)")

        hello_over = build_padded_tls13_client_hello(65537)
        assert len(hello_over) == 65537
        res_over = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=103,
            counter=1,
            plaintext_after_prelude=hello_over,
            timeout=6.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res_over, "65537B oversized ClientHello (> 64 KiB wire cap)")


def t2_r1_02_byte_by_byte_fragmented_hello(ctx: TestContext) -> None:
    """Valid 76B prelude + ClientHello split across 1-5 byte TCP writes produces ServerHello."""
    with ctx.workspace("t2_r1_02") as ws:
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 4, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        res = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=103,
            counter=1,
            plaintext_after_prelude=build_tls13_client_hello(),
            timeout=6.0,
            fragment_sizes=[76, 1, 2, 3, 5],
            fragment_delay_s=0.001,
            wait_for_close=False,
        )
        _assert_server_hello(res, "fragmented ClientHello")


def t2_r1_03_eof_mid_clienthello(ctx: TestContext) -> None:
    """EOF mid-ClientHello emits 0B, closes with RST, and does NOT burn replay counter."""
    with ctx.workspace("t2_r1_03") as ws:
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        full_hello = build_tls13_client_hello()

        res_eof = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=104,
            counter=1,
            plaintext_after_prelude=full_hello[:30],
            timeout=5.0,
            shutdown_wr=True,
            wait_for_close=True,
        )
        _assert_silent_rst(res_eof, "EOF mid-ClientHello")

        res_retry = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=104,
            counter=1,
            plaintext_after_prelude=full_hello,
            timeout=5.0,
            wait_for_close=False,
        )
        _assert_server_hello(res_retry, "resend same (I, C) after mid-ClientHello EOF")


def t2_r1_04_racing_duplicate_clienthello(ctx: TestContext) -> None:
    """Two barrier-synced connections racing the same (I, C) yield 1 ServerHello and 1 silent RST."""
    with ctx.workspace("t2_r1_04") as ws:
        srv, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 3, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        prelude, nonce = encode_prelude(mk, identity=105, counter=1)
        hello_ct = ChaCha20Stream(mk.tcp_c2s, nonce).apply(build_tls13_client_hello())

        s1 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=4.0)
        s2 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=4.0)
        try:
            s1.sendall(prelude)
            s2.sendall(prelude)
            barrier = threading.Barrier(2)
            results: List[ProbeResult] = []
            lock = threading.Lock()

            def _race(sock: socket.socket) -> None:
                s2c = ChaCha20Stream(mk.tcp_s2c, nonce)
                barrier.wait(timeout=5.0)
                sock.sendall(hello_ct)
                r = read_first_response(sock, timeout=4.5, decrypt_stream=s2c)
                with lock:
                    results.append(r)

            t1 = threading.Thread(target=_race, args=(s1,), daemon=True)
            t2 = threading.Thread(target=_race, args=(s2,), daemon=True)
            t1.start()
            t2.start()
            t1.join(timeout=8.0)
            t2.join(timeout=8.0)
            assert len(results) == 2

            winners = [r for r in results if len(r.received) >= 6]
            losers = [r for r in results if len(r.raw_received) == 0]
            assert len(winners) == 1, f"expected exactly 1 winner, got {len(winners)}: {results}"
            assert len(losers) == 1, f"expected exactly 1 silent loser, got {len(losers)}: {results}"
            _assert_server_hello(winners[0], "race winner")
            _assert_silent_rst(losers[0], "race loser")
            replays = srv.wait_for_metric(
                "uncrowned_king_server_mask_replay_rejects_total",
                lambda v: v >= 1,
                timeout=3.0,
            )
            assert replays == 1, f"expected 1 replay reject, got {replays}"
        finally:
            _close_all([s1, s2])


def t2_r1_05_high_bit_edge_preludes(ctx: TestContext) -> None:
    """Tail high bits all 0x00 and all 0x80 decode cleanly and preserve counter on corrupt hello."""
    with ctx.workspace("t2_r1_05") as ws:
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        hello = build_tls13_client_hello()

        for idx, hb in enumerate((0x00, 0x80), start=106):
            r_bad = MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                mk,
                identity=idx,
                counter=1,
                plaintext_after_prelude=b"\x63" * 64,
                high_bits_override=hb,
                timeout=5.0,
                wait_for_close=True,
            )
            _assert_silent_rst(r_bad, f"hb=0x{hb:02x} corrupt hello")

            r_ok = MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                mk,
                identity=idx,
                counter=1,
                plaintext_after_prelude=hello,
                high_bits_override=hb,
                timeout=5.0,
                wait_for_close=False,
            )
            _assert_server_hello(r_ok, f"hb=0x{hb:02x} valid hello after corrupt")


# ---------------------------------------------------------------------------
# R2 Boundaries (5 tests)
# ---------------------------------------------------------------------------

def t2_r2_01_pre_auth_limit_equals_1(ctx: TestContext) -> None:
    """max_pre_auth_connections=1, max_pre_auth_per_source=1 drops 2nd, allows 3rd after close."""
    with ctx.workspace("t2_r2_01") as ws:
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={
                "max_pre_auth_connections": 1,
                "max_pre_auth_per_source": 1,
                "handshake_timeout_seconds": 5,
            },
        )
        s1 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=2.0)
        s2: Optional[socket.socket] = None
        try:
            assert check_socket_closed(s1, timeout=0.05) == CloseKind.OPEN
            s2 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=2.0)
            r2 = read_until_close(s2, timeout=1.5)
            _assert_silent_rst(r2, "2nd socket with pre_auth_limit=1")
            assert r2.elapsed_s < 0.5
            s1.shutdown(socket.SHUT_WR)
            r1 = read_until_close(s1, timeout=6.5)
            _assert_silent_rst(r1, "1st socket silent drain close")
        finally:
            _close_all([s for s in (s1, s2) if s is not None])

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
        cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=8.0)
        assert cp.returncode == 0, f"3rd connection failed after 1st closed: {cp.stderr}"


def t2_r2_02_per_source_clamped_to_global(ctx: TestContext) -> None:
    """config-check rejects max_pre_auth_per_source > max_pre_auth_connections and accepts ==."""
    with ctx.workspace("t2_r2_02") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]

        bad_cfg = ws.write_secret(
            "bad.toml",
            build_server_toml(
                listen="127.0.0.1:9443",
                cert_path=certs.cert,
                key_path=certs.key,
                credentials=creds,
                limits={"max_pre_auth_connections": 4, "max_pre_auth_per_source": 5},
            ),
        )
        rc_bad = run_config_check(ctx.server_bin, bad_cfg)
        assert rc_bad.returncode != 0, "config-check accepted per_source > global"

        ok_cfg = ws.write_secret(
            "ok.toml",
            build_server_toml(
                listen="127.0.0.1:9443",
                cert_path=certs.cert,
                key_path=certs.key,
                credentials=creds,
                limits={"max_pre_auth_connections": 4, "max_pre_auth_per_source": 4},
            ),
        )
        rc_ok = run_config_check(ctx.server_bin, ok_cfg)
        assert rc_ok.returncode == 0, f"config-check rejected per_source == global: {rc_ok.stderr}"


def t2_r2_03_zero_pre_auth_limits_rejected(ctx: TestContext) -> None:
    """config-check rejects max_pre_auth_connections=0 and max_pre_auth_per_source=0."""
    with ctx.workspace("t2_r2_03") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]
        for field in ("max_pre_auth_connections", "max_pre_auth_per_source"):
            cfg = ws.write_secret(
                f"zero_{field}.toml",
                build_server_toml(
                    listen="127.0.0.1:9443",
                    cert_path=certs.cert,
                    key_path=certs.key,
                    credentials=creds,
                    limits={field: 0},
                ),
            )
            rc = run_config_check(ctx.server_bin, cfg)
            assert rc.returncode != 0, f"config-check unexpectedly accepted {field}=0"


def t2_r2_04_ipv4_mapped_ipv6_canonicalization(ctx: TestContext) -> None:
    """On [::] dual-stack listener, 127.0.0.1 (::ffff:127.0.0.1) is bucketed separately from ::1."""
    sources = discover_loopback_sources()
    assert "::1" in sources and "127.0.0.1" in sources
    with ctx.workspace("t2_r2_04") as ws:
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            listen_host="::",
            limits={
                "max_pre_auth_connections": 8,
                "max_pre_auth_per_source": 1,
                "handshake_timeout_seconds": 5,
            },
        )
        held: List[socket.socket] = []
        try:
            s1 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, source_addr="127.0.0.1", timeout=2.0)
            held.append(s1)
            assert check_socket_closed(s1, timeout=0.05) == CloseKind.OPEN

            s2 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, source_addr="127.0.0.1", timeout=2.0)
            held.append(s2)
            r2 = read_until_close(s2, timeout=1.5)
            _assert_silent_rst(r2, "2nd 127.0.0.1 connection over per_source=1")
            assert r2.elapsed_s < 0.5

            cli_cfg = ws.write_secret(
                "client_v6.toml",
                build_client_toml(
                    server_addr=f"tls://[::1]:{tcp_port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    masking={"enabled": True},
                ),
            )
            cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=8.0)
            assert cp.returncode == 0, f"::1 failed while 127.0.0.1 saturated: {cp.stderr}"
        finally:
            _close_all(held)


def t2_r2_05_burst_above_limit_no_fd_exhaustion(ctx: TestContext) -> None:
    """Burst of 60 concurrent silent sockets with max_pre_auth_connections=8 drops excess, keeps server healthy."""
    with ctx.workspace("t2_r2_05") as ws:
        _, tcp_port, obs_port, creds = _setup_server(
            ws,
            ctx,
            limits={
                "max_pre_auth_connections": 8,
                "max_pre_auth_per_source": 8,
                "handshake_timeout_seconds": 2,
                "auth_rate_limit_failures": 100,
            },
        )
        sockets: List[socket.socket] = []
        admitted_sockets: List[socket.socket] = []
        lock = threading.Lock()

        def _probe(_idx: int) -> ProbeResult:
            t0 = time.monotonic()
            try:
                s = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=3.0)
            except OSError as exc:
                if exc.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE):
                    return ProbeResult(
                        received=b"",
                        raw_received=b"",
                        close_kind=CloseKind.RST,
                        elapsed_s=time.monotonic() - t0,
                        error=str(exc),
                    )
                raise
            with lock:
                sockets.append(s)
            res = read_until_close(s, timeout=0.4)
            if res.close_kind == CloseKind.TIMEOUT:
                with lock:
                    admitted_sockets.append(s)
            return res

        def _drain(sock: socket.socket) -> ProbeResult:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return read_until_close(sock, timeout=3.5)

        try:
            with ThreadPoolExecutor(max_workers=60) as pool:
                results = list(pool.map(_probe, range(60)))
            rst_fast = [
                r for r in results if r.close_kind == CloseKind.RST and len(r.raw_received) == 0
            ]
            assert len(rst_fast) >= 52, (
                f"expected >= 52 immediate RSTs out of 60 burst sockets, got {len(rst_fast)}"
            )
            st, body = http_get("127.0.0.1", port=obs_port, path="/readyz", timeout=2.0)
            assert st == 200 and "ready" in body
            if admitted_sockets:
                with ThreadPoolExecutor(max_workers=len(admitted_sockets)) as drain_pool:
                    drain_results = list(drain_pool.map(_drain, admitted_sockets))
                for dr in drain_results:
                    _assert_silent_rst(dr, "admitted burst socket silent drain")
        finally:
            _close_all(sockets)

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
        cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=8.0)
        assert cp.returncode == 0, f"post-burst handshake failed: {cp.stderr}"


def t2_r2_06_default_per_source_32_enforced(ctx: TestContext) -> None:
    """With pre-auth limits omitted from [limits], default max_pre_auth_per_source=32 holds 32 sockets, RST-drops 33rd (0B), and another source succeeds."""
    sources = discover_loopback_sources()
    assert "::1" in sources and "127.0.0.1" in sources, (
        f"need both ::1 and 127.0.0.1, got {sources}"
    )
    with ctx.workspace("t2_r2_06") as ws:
        srv, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            listen_host="::",
            limits={"handshake_timeout_seconds": 10},
        )
        held: List[socket.socket] = []
        try:
            for _ in range(32):
                held.append(
                    MaskedTcpProbe.open_socket(
                        "127.0.0.1", tcp_port, source_addr="127.0.0.1", timeout=2.0
                    )
                )
            srv.wait_for_metric(
                "uncrowned_king_server_accepted_connections_total",
                lambda v: v >= 32,
                timeout=5.0,
            )
            for idx, s in enumerate(held):
                assert check_socket_closed(s, timeout=0.05) == CloseKind.OPEN, (
                    f"held socket #{idx + 1}/32 closed prematurely"
                )

            s33 = MaskedTcpProbe.open_socket(
                "127.0.0.1", tcp_port, source_addr="127.0.0.1", timeout=2.0
            )
            held.append(s33)
            r33 = read_until_close(s33, timeout=1.5)
            _assert_silent_rst(r33, "33rd socket over default max_pre_auth_per_source=32")
            assert r33.elapsed_s < 0.5, (
                f"expected immediate drop (<0.5s), took {r33.elapsed_s:.3f}s"
            )
            rej = srv.wait_for_metric(
                "uncrowned_king_server_rejected_pre_auth_connections_total",
                lambda v: v >= 1,
                timeout=3.0,
            )
            assert rej >= 1

            for idx in range(32):
                assert check_socket_closed(held[idx], timeout=0.05) == CloseKind.OPEN, (
                    f"held socket #{idx + 1}/32 closed when 33rd was dropped"
                )

            cli_cfg = ws.write_secret(
                "client_v6.toml",
                build_client_toml(
                    server_addr=f"tls://[::1]:{tcp_port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    masking={"enabled": True},
                ),
            )
            cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=8.0)
            assert cp.returncode == 0, (
                f"::1 client handshake failed while 127.0.0.1 held 32 default slots: {cp.stderr}"
            )
        finally:
            _close_all(held)


# ---------------------------------------------------------------------------
# R3 Boundaries (5 tests)
# ---------------------------------------------------------------------------

def t2_r3_01_masked_quic_sub_nonce_and_12b_udp(ctx: TestContext) -> None:
    """0B, 1B, 11B, 12B, 13B UDP datagrams to masked QUIC produce 0 replies; client succeeds afterward."""
    with ctx.workspace("t2_r3_01") as ws:
        quic_port = free_udp_port("127.0.0.1")
        _, _, _, creds = _setup_server(
            ws,
            ctx,
            quic_port=quic_port,
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
        )
        with QuicProbeSocket("127.0.0.1", quic_port) as qp:
            for pkt in (b"", b"\x01", os.urandom(11), os.urandom(12), os.urandom(13)):
                qp.send_raw(pkt)
            replies = qp.recv_packets(timeout=0.4)
            assert replies == [], f"expected 0 replies to sub-nonce UDP, got {len(replies)}"

        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{quic_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                masking={"enabled": True, "quic": True},
            ),
        )
        cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=10.0)
        assert cp.returncode == 0, f"masked QUIC client failed after sub-nonce probes: {cp.stderr}"


def t2_r3_02_masked_quic_oversized_udp_datagram(ctx: TestContext) -> None:
    """1500B & 4096B random UDP datagrams are dropped silently; captured masked QUIC wire packets obey <= 1452B (1440+12) / <= 1472B (1460+12)."""
    with ctx.workspace("t2_r3_02") as ws:
        http_srv = ws.enter(LocalHttpServer())
        udp_echo = ws.enter(LocalUdpEchoServer())
        quic_port = free_udp_port("127.0.0.1")
        _, _, _, creds = _setup_server(
            ws,
            ctx,
            quic_port=quic_port,
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
            policy_ports=[http_srv.port, udp_echo.port],
        )
        with QuicProbeSocket("127.0.0.1", quic_port) as qp:
            qp.send_raw(os.urandom(1500))
            qp.send_raw(os.urandom(4096))
            assert qp.recv_packets(timeout=0.4) == []

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

        expected_http = deterministic_bytes(262144, seed=0x2302)
        http_srv.register("/t2_r3_02", expected_http)
        st, _, body = Socks5Client.socks5_http_get(
            "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, path="/t2_r3_02"
        )
        assert st == 200 and hashlib.sha256(body).digest() == hashlib.sha256(expected_http).digest()

        payloads = [deterministic_bytes(100, 1), deterministic_bytes(1200, 2), deterministic_bytes(1350, 3)]
        echoed = Socks5Client.socks5_udp_exchange(
            "127.0.0.1", socks_port, "127.0.0.1", udp_echo.port, payloads, timeout=15.0
        )
        assert echoed == payloads

        c2s_pkts, s2c_pkts = proxy.snapshot()
        all_pkts = c2s_pkts + s2c_pkts
        assert len(all_pkts) > 0, "expected captured masked QUIC wire datagrams"
        oversized = [len(p) for p in all_pkts if len(p) > masked_max_wire_size]
        assert not oversized, (
            f"masked QUIC wire datagrams exceeded {masked_max_wire_size}B "
            f"(apply_masked_mtu 1440+12): max={max(oversized)}"
        )


def t2_r3_03_quic_window_config_constraints(ctx: TestContext) -> None:
    """config-check rejects quic_connection_receive_window < quic_stream_receive_window and accepts ==."""
    with ctx.workspace("t2_r3_03") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]

        bad_cfg = ws.write_secret(
            "bad_win.toml",
            build_server_toml(
                listen="127.0.0.1:9443",
                quic_listen="127.0.0.1:9443",
                cert_path=certs.cert,
                key_path=certs.key,
                credentials=creds,
                limits={
                    "quic_stream_receive_window": 2_097_152,
                    "quic_connection_receive_window": 1_048_576,
                },
            ),
        )
        assert run_config_check(ctx.server_bin, bad_cfg).returncode != 0

        ok_cfg = ws.write_secret(
            "ok_win.toml",
            build_server_toml(
                listen="127.0.0.1:9443",
                quic_listen="127.0.0.1:9443",
                cert_path=certs.cert,
                key_path=certs.key,
                credentials=creds,
                limits={
                    "quic_stream_receive_window": 1_048_576,
                    "quic_connection_receive_window": 1_048_576,
                },
            ),
        )
        rc_ok = run_config_check(ctx.server_bin, ok_cfg)
        assert rc_ok.returncode == 0, f"equal QUIC windows rejected: {rc_ok.stderr}"


def t2_r3_04_masked_quic_ipv6_loopback(ctx: TestContext) -> None:
    """Masked QUIC server on [::1]:port relays HTTP over quic://[::1]:port."""
    sources = discover_loopback_sources()
    assert "::1" in sources
    with ctx.workspace("t2_r3_04") as ws:
        http_srv = ws.enter(LocalHttpServer())
        quic_port = free_udp_port("::1")
        _, _, _, creds = _setup_server(
            ws,
            ctx,
            listen_host="::1",
            quic_host="::1",
            quic_port=quic_port,
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
            policy_ports=[http_srv.port],
        )
        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli_cfg = ws.write_secret(
            "client_v6_quic.toml",
            build_client_toml(
                server_addr=f"quic://[::1]:{quic_port}",
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
        st, _h, body = Socks5Client.socks5_http_get(
            "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/32768"
        )
        assert st == 200 and body == deterministic_bytes(32768)


def t2_r3_05_masked_quic_retry_enabled_with_masking(ctx: TestContext) -> None:
    """Masked QUIC handshake triggers stateless Retry (quic_retries_total >= 1)."""
    with ctx.workspace("t2_r3_05") as ws:
        quic_port = free_udp_port("127.0.0.1")
        srv, _, _, creds = _setup_server(
            ws,
            ctx,
            quic_port=quic_port,
            masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
        )
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{quic_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                masking={"enabled": True, "quic": True},
            ),
        )
        cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=12.0)
        assert cp.returncode == 0, f"masked QUIC handshake failed: {cp.stderr}"
        retries = srv.wait_for_metric(
            "uncrowned_king_server_quic_retries_total",
            lambda v: v >= 1,
            timeout=3.0,
        )
        assert retries >= 1


# ---------------------------------------------------------------------------
# R4 Boundaries (5 tests)
# ---------------------------------------------------------------------------

def t2_r4_01_prelude_consumes_most_of_deadline(ctx: TestContext) -> None:
    """2.2s Phase 1 delay into 3s shared deadline closes Phase 2 with RST at ~3.0s (<=4.0s)."""
    with ctx.workspace("t2_r4_01") as ws:
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 3, "auth_rate_limit_failures": 10},
        )
        with StallProxy(
            "127.0.0.1", tcp_port, phase1_delay_s=2.2, hold_phase2=True
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
                target=lambda: run_client_handshake(ctx.client_bin, cli_cfg, timeout=12.0),
                daemon=True,
            )
            t.start()
            rec = proxy.wait_for_session_close(index=0, timeout=10.0)
            t.join(timeout=10.0)
            assert rec.server_first_reply_at is not None
            assert rec.server_close_kind == CloseKind.RST
            assert rec.elapsed_s is not None and 2.5 <= rec.elapsed_s <= 4.0, (
                f"expected total close near 3.0s ([2.5, 4.0]), got {rec.elapsed_s}"
            )


def t2_r4_02_double_check_after_auth_race(ctx: TestContext) -> None:
    """Fast auth completes cleanly; AuthResponse delayed past 2.0s deadline closes via RST."""
    with ctx.workspace("t2_r4_02") as ws:
        http_srv = ws.enter(LocalHttpServer())
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
            policy_ports=[http_srv.port],
        )
        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        cli_ok_cfg = ws.write_secret(
            "client_ok.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                masking={"enabled": True},
            ),
        )
        with UkClientProcess(
            ctx.client_bin, cli_ok_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
        ) as cli:
            cli.wait_ready(require_session=True, timeout=10.0)
            st, _h, body = Socks5Client.socks5_http_get(
                "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/16384"
            )
            assert st == 200 and body == deterministic_bytes(16384)

        with StallProxy(
            "127.0.0.1", tcp_port, phase1_delay_s=0.0, phase2_delay_s=2.5, hold_phase2=False
        ) as proxy:
            cli_late_cfg = ws.write_secret(
                "client_late.toml",
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
                target=lambda: run_client_handshake(ctx.client_bin, cli_late_cfg, timeout=10.0),
                daemon=True,
            )
            t.start()
            rec = proxy.wait_for_session_close(index=0, timeout=8.0)
            t.join(timeout=8.0)
            assert rec.server_close_kind == CloseKind.RST
            assert rec.elapsed_s is not None and 1.5 <= rec.elapsed_s <= 3.2


def t2_r4_03_unmasked_path_unaffected(ctx: TestContext) -> None:
    """Unmasked TCP server completes valid handshake and handles bad TLS without masked dwell."""
    with ctx.workspace("t2_r4_03") as ws:
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2},
            masking=None,
        )
        cli_cfg = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=ws.path / "server-ca-cert.pem",
                key_id=str(creds[0]["key_id"]),
                secret=str(creds[0]["secret"]),
                masking=None,
            ),
        )
        cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=8.0)
        assert cp.returncode == 0, f"unmasked client failed: {cp.stderr}"

        res_bad = MaskedTcpProbe.send_and_probe(
            "127.0.0.1",
            tcp_port,
            b"\x16\x03\x01\x00\x05\xff\xff\xff\xff\xff",
            timeout=3.0,
            wait_for_close=True,
        )
        assert res_bad.elapsed_s < 1.0, (
            f"unmasked bad TLS unexpectedly entered masked dwell: {res_bad.elapsed_s:.3f}s"
        )


def t2_r4_04_short_prelude_75_bytes_exact(ctx: TestContext) -> None:
    """Exact 75B prelude (1B short) held open emits 0B, dwells [0.8s, 3.5s], closes RST."""
    with ctx.workspace("t2_r4_04") as ws:
        srv, tcp_port, _, _ = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        sock = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=5.0)
        try:
            sock.sendall(b"\xab" * 75)
            res = read_until_close(sock, timeout=5.0)
            _assert_silent_rst(res, "75B short prelude")
            assert 0.8 <= res.elapsed_s <= 3.5, (
                f"expected dwell in [0.8s, 3.5s], got {res.elapsed_s:.3f}s"
            )
            rej = srv.wait_for_metric(
                "uncrowned_king_server_mask_prelude_rejects_total",
                lambda v: v >= 1,
                timeout=3.0,
            )
            assert rej == 1
        finally:
            sock.close()


def t2_r4_05_client_disconnect_flushes_target(ctx: TestContext) -> None:
    """Carrier disconnect after uploading 64 KiB flushes all 64 KiB cleanly to slow-reading target."""
    with ctx.workspace("t2_r4_05") as ws:
        echo_srv = ws.enter(
            LocalTcpEchoServer(read_chunk_size=1024, read_delay_s=0.01, echo=False)
        )
        _, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"tcp_half_close_timeout_seconds": 10, "shutdown_timeout_seconds": 10},
            policy_ports=[echo_srv.port],
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

        payload = deterministic_bytes(65536, seed=0x464C)
        sock = Socks5Client.socks5_connect(
            "127.0.0.1", socks_port, "127.0.0.1", echo_srv.port, timeout=10.0
        )
        try:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
        finally:
            sock.close()

        cli.wait_for_metric(
            "uncrowned_king_client_relay_bytes_total",
            lambda v: v >= 65536,
            labels={"protocol": "tcp", "direction": "local_to_server"},
            timeout=10.0,
        )
        # Disconnect the carrier while the slow target is still draining.
        cli.stop()

        received = echo_srv.wait_for_total_received(65536, timeout=15.0)
        assert received == 65536, f"expected 65536 flushed bytes, got {received}"
        deadline = time.monotonic() + 5.0
        with echo_srv._cond:
            while not echo_srv.per_conn_received:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                echo_srv._cond.wait(timeout=min(0.05, rem))
        assert echo_srv.per_conn_received and echo_srv.per_conn_received[0] == payload


# ---------------------------------------------------------------------------
# R5 Boundaries (5 tests)
# ---------------------------------------------------------------------------

def t2_r5_01_counter_zero_rejected_after_hmac(ctx: TestContext) -> None:
    """Valid HMAC tag for counter=0 is rejected silently (0B, RST, mask_prelude_rejects_total==1)."""
    with ctx.workspace("t2_r5_01") as ws:
        srv, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        res = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=501,
            counter=0,
            plaintext_after_prelude=build_tls13_client_hello(),
            allow_zero_counter=True,
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(res, "counter=0 with valid HMAC")
        rej = srv.wait_for_metric(
            "uncrowned_king_server_mask_prelude_rejects_total",
            lambda v: v >= 1,
            timeout=3.0,
        )
        assert rej == 1


def t2_r5_02_counter_max_2p48_minus_1(ctx: TestContext) -> None:
    """Maximum 48-bit counter (1<<48)-1 succeeds once and blocks replay."""
    with ctx.workspace("t2_r5_02") as ws:
        srv, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        hello = build_tls13_client_hello()

        r1 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=502,
            counter=MAX_COUNTER,
            plaintext_after_prelude=hello,
            timeout=5.0,
            wait_for_close=False,
        )
        _assert_server_hello(r1, "MAX_COUNTER initial")

        r2 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=502,
            counter=MAX_COUNTER,
            plaintext_after_prelude=hello,
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(r2, "MAX_COUNTER replay")
        assert srv.wait_for_metric(
            "uncrowned_king_server_mask_replay_rejects_total",
            lambda v: v >= 1,
            timeout=3.0,
        ) == 1


def t2_r5_03_window_edge_1023_vs_1024(ctx: TestContext) -> None:
    """After ctr=2000, ctr=977 (diff 1023) is accepted while ctr=976 (diff 1024) is rejected."""
    with ctx.workspace("t2_r5_03") as ws:
        srv, tcp_port, _, creds = _setup_server(
            ws,
            ctx,
            limits={"handshake_timeout_seconds": 2, "auth_rate_limit_failures": 10},
        )
        mk = derive_mask_keys(creds[0]["key_id"], creds[0]["secret"])
        hello = build_tls13_client_hello()

        _assert_server_hello(
            MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                mk,
                identity=503,
                counter=2000,
                plaintext_after_prelude=hello,
                timeout=5.0,
                wait_for_close=False,
            ),
            "ctr=2000",
        )
        _assert_server_hello(
            MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                mk,
                identity=503,
                counter=977,
                plaintext_after_prelude=hello,
                timeout=5.0,
                wait_for_close=False,
            ),
            "ctr=977 (diff=1023)",
        )
        r_stale = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            mk,
            identity=503,
            counter=976,
            plaintext_after_prelude=hello,
            timeout=5.0,
            wait_for_close=True,
        )
        _assert_silent_rst(r_stale, "ctr=976 (diff=1024)")
        assert srv.wait_for_metric(
            "uncrowned_king_server_mask_replay_rejects_total",
            lambda v: v >= 1,
            timeout=3.0,
        ) == 1


def t2_r5_04_64kib_exact_and_64kib_plus_1_relay(ctx: TestContext) -> None:
    """Masked TCP SOCKS5 echo of exact 65535, 65536, and 65537 byte payloads."""
    with ctx.workspace("t2_r5_04") as ws:
        echo_srv = ws.enter(LocalTcpEchoServer())
        _, tcp_port, _, creds = _setup_server(
            ws, ctx, policy_ports=[echo_srv.port]
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

        for sz in (65535, 65536, 65537):
            payload = deterministic_bytes(sz, seed=sz)
            got = Socks5Client.socks5_echo(
                "127.0.0.1", socks_port, "127.0.0.1", echo_srv.port, payload, timeout=15.0
            )
            assert got == payload, f"mismatch for {sz}-byte echo (got {len(got)} bytes)"


def t2_r5_05_coalesced_segment_split_at_proxy(ctx: TestContext) -> None:
    """Client coalesces >=76+5B first segment while proxy fragments forwarding into 17B chunks."""
    with ctx.workspace("t2_r5_05") as ws:
        http_srv = ws.enter(LocalHttpServer())
        _, tcp_port, _, creds = _setup_server(
            ws, ctx, policy_ports=[http_srv.port]
        )
        with TransparentFirstSegmentProxy(
            "127.0.0.1", tcp_port, split_chunk_size=17
        ) as proxy:
            socks_port = free_tcp_port("127.0.0.1")
            cli_obs = free_tcp_port("127.0.0.1")
            cli_cfg = ws.write_secret(
                "client.toml",
                build_client_toml(
                    server_addr=f"tls://127.0.0.1:{proxy.listen_port}",
                    ca_cert_path=ws.path / "server-ca-cert.pem",
                    key_id=str(creds[0]["key_id"]),
                    secret=str(creds[0]["secret"]),
                    observability_listen=f"127.0.0.1:{cli_obs}",
                    masking={"enabled": True, "prelude_policy": "fade"},
                ),
            )
            cli = ws.enter(
                UkClientProcess(
                    ctx.client_bin, cli_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
                )
            )
            cli.wait_ready(require_session=True, timeout=12.0)
            seg = proxy.wait_for_first_segment(timeout=5.0)
            assert len(seg) >= WIRE_PRELUDE_LEN + 5, (
                f"expected coalesced >= 81B first segment, got {len(seg)}B"
            )
            st, _h, body = Socks5Client.socks5_http_get(
                "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/32768"
            )
            assert st == 200 and body == deterministic_bytes(32768)


# ---------------------------------------------------------------------------
# R6 Boundaries (7 tests)
# ---------------------------------------------------------------------------

def t2_r6_01_masking_replay_identities_bounds(ctx: TestContext) -> None:
    """config-check rejects replay_identities 1023 & 1048577, accepts 1024 & 1048576."""
    with ctx.workspace("t2_r6_01") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]
        for val in (1023, 1_048_577):
            cfg = ws.write_secret(
                f"bad_{val}.toml",
                build_server_toml(
                    listen="127.0.0.1:9443",
                    cert_path=certs.cert,
                    key_path=certs.key,
                    credentials=creds,
                    masking={"enabled": True, "replay_identities": val},
                ),
            )
            assert run_config_check(ctx.server_bin, cfg).returncode != 0, (
                f"replay_identities={val} should be rejected"
            )
        for val in (1024, 1_048_576):
            cfg = ws.write_secret(
                f"ok_{val}.toml",
                build_server_toml(
                    listen="127.0.0.1:9443",
                    cert_path=certs.cert,
                    key_path=certs.key,
                    credentials=creds,
                    masking={"enabled": True, "replay_identities": val},
                ),
            )
            rc = run_config_check(ctx.server_bin, cfg)
            assert rc.returncode == 0, f"replay_identities={val} rejected: {rc.stderr}"


def t2_r6_02_quic_masking_missing_key_id(ctx: TestContext) -> None:
    """config-check rejects masking.quic=true without quic_key_id or with nonexistent quic_key_id."""
    with ctx.workspace("t2_r6_02") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]

        no_kid = ws.write_secret(
            "no_kid.toml",
            build_server_toml(
                listen="127.0.0.1:9443",
                quic_listen="127.0.0.1:9443",
                cert_path=certs.cert,
                key_path=certs.key,
                credentials=creds,
                masking={"enabled": True, "quic": True},
            ),
        )
        assert run_config_check(ctx.server_bin, no_kid).returncode != 0

        bad_kid = ws.write_secret(
            "bad_kid.toml",
            build_server_toml(
                listen="127.0.0.1:9443",
                quic_listen="127.0.0.1:9443",
                cert_path=certs.cert,
                key_path=certs.key,
                credentials=creds,
                masking={"enabled": True, "quic": True, "quic_key_id": "nonexistent"},
            ),
        )
        assert run_config_check(ctx.server_bin, bad_kid).returncode != 0


def t2_r6_03_sighup_rejects_masking_change(ctx: TestContext) -> None:
    """Editing [masking] on disk + SIGHUP fails reload and leaves active masking unchanged."""
    with ctx.workspace("t2_r6_03") as ws:
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
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_cfg, f"127.0.0.1:{obs_port}")
        )
        srv.wait_ready()

        ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                observability_listen=f"127.0.0.1:{obs_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=pol_path,
                credentials=creds,
                masking={"enabled": False},
            ),
        )
        srv.send_sighup()
        fails = srv.wait_for_metric(
            "uncrowned_king_server_config_reload_failures_total",
            lambda v: v >= 1,
            timeout=5.0,
        )
        assert fails == 1
        assert srv.metric("uncrowned_king_server_security_generation") == 1

        # Active masked mode still works for masked client.
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
        cp = run_client_handshake(ctx.client_bin, cli_cfg, timeout=8.0)
        assert cp.returncode == 0, f"masked client failed after rejected SIGHUP: {cp.stderr}"


def t2_r6_04_sighup_rotates_tcp_mask_keys(ctx: TestContext) -> None:
    """SIGHUP adding k2 allows new k2 masked client while existing k1 session continues relaying."""
    with ctx.workspace("t2_r6_04") as ws:
        http_srv = ws.enter(LocalHttpServer())
        certs = ws.generate_certs()
        k1 = {"key_id": "k1", "secret": make_secret()}
        k2 = {"key_id": "k2", "secret": make_secret()}
        tcp_port = free_tcp_port("127.0.0.1")
        obs_port = free_tcp_port("127.0.0.1")
        pol_path = ws.write_secret("policy.toml", allow_loopback_policy(ports=[http_srv.port]))

        srv_cfg = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                observability_listen=f"127.0.0.1:{obs_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=pol_path,
                credentials=[k1],
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_cfg, f"127.0.0.1:{obs_port}")
        )
        srv.wait_ready()

        socks_port = free_tcp_port("127.0.0.1")
        cli_obs = free_tcp_port("127.0.0.1")
        c1_cfg = ws.write_secret(
            "client_k1.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=str(k1["secret"]),
                observability_listen=f"127.0.0.1:{cli_obs}",
                masking={"enabled": True},
            ),
        )
        cli1 = ws.enter(
            UkClientProcess(
                ctx.client_bin, c1_cfg, f"127.0.0.1:{socks_port}", f"127.0.0.1:{cli_obs}"
            )
        )
        cli1.wait_ready(require_session=True, timeout=10.0)

        ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                observability_listen=f"127.0.0.1:{obs_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=pol_path,
                credentials=[k1, k2],
                masking={"enabled": True},
            ),
        )
        srv.send_sighup()
        gen = srv.wait_for_metric(
            "uncrowned_king_server_security_generation",
            lambda v: v >= 2,
            timeout=5.0,
        )
        assert gen == 2

        c2_cfg = ws.write_secret(
            "client_k2.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k2",
                secret=str(k2["secret"]),
                masking={"enabled": True},
            ),
        )
        cp2 = run_client_handshake(ctx.client_bin, c2_cfg, timeout=8.0)
        assert cp2.returncode == 0, f"k2 masked client failed after SIGHUP rotation: {cp2.stderr}"

        st, _h, body = Socks5Client.socks5_http_get(
            "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, "/bytes/16384"
        )
        assert st == 200 and body == deterministic_bytes(16384)


def t2_r6_05_0644_config_or_key_rejected(ctx: TestContext) -> None:
    """chmod 0644 on server.toml and separately on server-key.pem fails config-check."""
    with ctx.workspace("t2_r6_05") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]
        cfg = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen="127.0.0.1:9443",
                cert_path=certs.cert,
                key_path=certs.key,
                credentials=creds,
            ),
        )
        assert run_config_check(ctx.server_bin, cfg).returncode == 0

        os.chmod(cfg, 0o644)
        assert run_config_check(ctx.server_bin, cfg).returncode != 0, (
            "0644 server.toml should be rejected"
        )
        os.chmod(cfg, 0o600)

        os.chmod(certs.key, 0o644)
        assert run_config_check(ctx.server_bin, cfg).returncode != 0, (
            "0644 server-key.pem should be rejected"
        )
        os.chmod(certs.key, 0o600)
        assert run_config_check(ctx.server_bin, cfg).returncode == 0


def t2_r6_06_ipv4_mapped_observability_rejected(ctx: TestContext) -> None:
    """config-check rejects IPv4-mapped wildcard [::ffff:0.0.0.0]:9090 and wildcards."""
    with ctx.workspace("t2_r6_06") as ws:
        certs = ws.generate_certs()
        creds = [{"key_id": "k1", "secret": make_secret()}]
        for idx, bind in enumerate(("[::ffff:0.0.0.0]:9090", "0.0.0.0:9090", "[::]:9090")):
            cfg = ws.write_secret(
                f"obs_{idx}.toml",
                build_server_toml(
                    listen="127.0.0.1:9443",
                    observability_listen=bind,
                    cert_path=certs.cert,
                    key_path=certs.key,
                    credentials=creds,
                ),
            )
            assert run_config_check(ctx.server_bin, cfg).returncode != 0, (
                f"observability_listen={bind!r} should be rejected"
            )


def t2_r6_07_sighup_rejects_pre_auth_limit_change(ctx: TestContext) -> None:
    """Editing max_pre_auth_connections or max_pre_auth_per_source + SIGHUP increments reload_failures."""
    with ctx.workspace("t2_r6_07") as ws:
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
                limits={"max_pre_auth_connections": 16, "max_pre_auth_per_source": 4},
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_cfg, f"127.0.0.1:{obs_port}")
        )
        srv.wait_ready()

        ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                observability_listen=f"127.0.0.1:{obs_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=pol_path,
                credentials=creds,
                limits={"max_pre_auth_connections": 32, "max_pre_auth_per_source": 4},
                masking={"enabled": True},
            ),
        )
        srv.send_sighup()
        assert srv.wait_for_metric(
            "uncrowned_king_server_config_reload_failures_total",
            lambda v: v >= 1,
            timeout=5.0,
        ) == 1

        ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                observability_listen=f"127.0.0.1:{obs_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=pol_path,
                credentials=creds,
                limits={"max_pre_auth_connections": 16, "max_pre_auth_per_source": 8},
                masking={"enabled": True},
            ),
        )
        srv.send_sighup()
        assert srv.wait_for_metric(
            "uncrowned_king_server_config_reload_failures_total",
            lambda v: v >= 2,
            timeout=5.0,
        ) == 2


# ---------------------------------------------------------------------------
# Test Discovery
# ---------------------------------------------------------------------------

def collect_tests(ctx: TestContext) -> List[E2ETestCase]:
    del ctx
    specs: List[Tuple[str, object]] = [
        ("R1", t2_r1_01_clienthello_exact_64kib_vs_64kib_plus_1),
        ("R1", t2_r1_02_byte_by_byte_fragmented_hello),
        ("R1", t2_r1_03_eof_mid_clienthello),
        ("R1", t2_r1_04_racing_duplicate_clienthello),
        ("R1", t2_r1_05_high_bit_edge_preludes),
        ("R2", t2_r2_01_pre_auth_limit_equals_1),
        ("R2", t2_r2_02_per_source_clamped_to_global),
        ("R2", t2_r2_03_zero_pre_auth_limits_rejected),
        ("R2", t2_r2_04_ipv4_mapped_ipv6_canonicalization),
        ("R2", t2_r2_05_burst_above_limit_no_fd_exhaustion),
        ("R2", t2_r2_06_default_per_source_32_enforced),
        ("R3", t2_r3_01_masked_quic_sub_nonce_and_12b_udp),
        ("R3", t2_r3_02_masked_quic_oversized_udp_datagram),
        ("R3", t2_r3_03_quic_window_config_constraints),
        ("R3", t2_r3_04_masked_quic_ipv6_loopback),
        ("R3", t2_r3_05_masked_quic_retry_enabled_with_masking),
        ("R4", t2_r4_01_prelude_consumes_most_of_deadline),
        ("R4", t2_r4_02_double_check_after_auth_race),
        ("R4", t2_r4_03_unmasked_path_unaffected),
        ("R4", t2_r4_04_short_prelude_75_bytes_exact),
        ("R4", t2_r4_05_client_disconnect_flushes_target),
        ("R5", t2_r5_01_counter_zero_rejected_after_hmac),
        ("R5", t2_r5_02_counter_max_2p48_minus_1),
        ("R5", t2_r5_03_window_edge_1023_vs_1024),
        ("R5", t2_r5_04_64kib_exact_and_64kib_plus_1_relay),
        ("R5", t2_r5_05_coalesced_segment_split_at_proxy),
        ("R6", t2_r6_01_masking_replay_identities_bounds),
        ("R6", t2_r6_02_quic_masking_missing_key_id),
        ("R6", t2_r6_03_sighup_rejects_masking_change),
        ("R6", t2_r6_04_sighup_rotates_tcp_mask_keys),
        ("R6", t2_r6_05_0644_config_or_key_rejected),
        ("R6", t2_r6_06_ipv4_mapped_observability_rejected),
        ("R6", t2_r6_07_sighup_rejects_pre_auth_limit_change),
    ]
    return [
        E2ETestCase(
            name=fn.__name__,
            tier=2,
            fn=fn,
            requirement=req,
            description=(fn.__doc__ or "").splitlines()[0],
        )
        for req, fn in specs
    ]
