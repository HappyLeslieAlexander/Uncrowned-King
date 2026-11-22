"""Tier 4: Real-World Workload E2E Scenarios (R1–R6) for Uncrowned King.

Covers 6 concurrent multi-client application scenarios:
  t4_01: Concurrent multi-client masked TCP (fade/full8/low7) HTTP mix under 30 probes
  t4_02: Concurrent masked QUIC + TCP clients (HTTP + SOCKS5 UDP) under 1,000 invalid UDP datagrams
  t4_03: Live SIGHUP TLS cert + credential rotation under active /slow masked stream
  t4_04: Multi-source pre-admission saturation (::1, fe80::1%lo0) with legit 127.0.0.1 client
  t4_05: Carrier pool saturation (max_carrier_sessions=2) & SSRF/egress policy enforcement (0x02)
  t4_06: Graceful SIGTERM shutdown drain under 3 active /slow masked streams
"""

import errno
import hashlib
import os
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from .uk_harness import (
        E2ETestCase,
        LocalHttpServer,
        LocalUdpEchoServer,
        TestContext,
        UkClientProcess,
        UkServerProcess,
        allow_loopback_policy,
        build_client_toml,
        build_server_toml,
        deterministic_bytes,
        discover_loopback_sources,
        free_tcp_port,
        free_udp_port,
        http_get,
        make_secret,
        run_client_handshake,
    )
    from .uk_wire import (
        QUIC_V1,
        WIRE_PRELUDE_LEN,
        CloseKind,
        MaskedTcpProbe,
        ProbeResult,
        QuicProbeSocket,
        Socks5Client,
        Socks5Error,
        build_quic_initial_probe,
        build_tls12_client_hello,
        check_socket_closed,
        derive_mask_keys,
        read_until_close,
    )
except ImportError:
    from uk_harness import (
        E2ETestCase,
        LocalHttpServer,
        LocalUdpEchoServer,
        TestContext,
        UkClientProcess,
        UkServerProcess,
        allow_loopback_policy,
        build_client_toml,
        build_server_toml,
        deterministic_bytes,
        discover_loopback_sources,
        free_tcp_port,
        free_udp_port,
        http_get,
        make_secret,
        run_client_handshake,
    )
    from uk_wire import (
        QUIC_V1,
        WIRE_PRELUDE_LEN,
        CloseKind,
        MaskedTcpProbe,
        ProbeResult,
        QuicProbeSocket,
        Socks5Client,
        Socks5Error,
        build_quic_initial_probe,
        build_tls12_client_hello,
        check_socket_closed,
        derive_mask_keys,
        read_until_close,
    )


def _close_sockets(sockets: List[socket.socket]) -> None:
    for s in sockets:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# T4-01: Concurrent Multi-Client Masked TCP + HTTP Mix under Probe Storm
# ---------------------------------------------------------------------------

def t4_01_concurrent_multi_client_masked_tcp_under_probes(ctx: TestContext) -> None:
    """3 uk-clients (fade, full8, low7) execute 18 concurrent HTTP GET/POST transfers while 30 invalid/corrupt-hello probes run concurrently."""
    with ctx.workspace("t4_01") as ws:
        certs = ws.generate_certs()
        secret = make_secret()
        keys = derive_mask_keys("k1", secret)

        http_srv = ws.enter(LocalHttpServer())
        policy_toml = ws.write_secret("policy.toml", allow_loopback_policy(ports=[http_srv.port]))
        srv_port = free_tcp_port()
        srv_obs = free_tcp_port()

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{srv_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[{"key_id": "k1", "secret": secret}],
                limits={
                    "max_sessions": 64,
                    "max_handshakes": 64,
                    "max_streams": 64,
                    "handshake_timeout_seconds": 2,
                    "auth_rate_limit_failures": 0,
                },
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        policies = ("fade", "full8", "low7")
        client_socks: List[int] = []
        for idx, pol in enumerate(policies):
            c_socks = free_tcp_port()
            c_obs = free_tcp_port()
            c_toml = ws.write_secret(
                f"client_{pol}.toml",
                build_client_toml(
                    server_addr=f"tls://127.0.0.1:{srv_port}",
                    ca_cert_path=certs.ca_cert,
                    key_id="k1",
                    secret=secret,
                    observability_listen=f"127.0.0.1:{c_obs}",
                    extra={"max_carrier_sessions": 2},
                    masking={"enabled": True, "prelude_policy": pol},
                ),
            )
            cli = ws.enter(
                UkClientProcess(
                    ctx.client_bin,
                    c_toml,
                    socks_listen=f"127.0.0.1:{c_socks}",
                    observability_listen=f"127.0.0.1:{c_obs}",
                )
            )
            cli.wait_ready(require_session=True, timeout=15.0)
            client_socks.append(c_socks)

        sizes = [1024, 16384, 65537, 131072, 262144, 524288]
        total_workers = 18 + 30
        barrier = threading.Barrier(total_workers, timeout=20.0)
        errors: List[str] = []
        err_lock = threading.Lock()

        def http_worker(worker_idx: int) -> None:
            socks_port = client_socks[worker_idx % 3]
            size = sizes[worker_idx % len(sizes)]
            is_post = (worker_idx % 2) == 1
            try:
                barrier.wait()
                if is_post:
                    payload = deterministic_bytes(size, seed=0x4010 + worker_idx)
                    st, _, resp = Socks5Client.socks5_http_post(
                        "127.0.0.1",
                        socks_port,
                        "127.0.0.1",
                        http_srv.port,
                        path="/sha256",
                        body=payload,
                        timeout=25.0,
                    )
                    assert st == 200, f"worker {worker_idx} POST HTTP {st}"
                    assert resp.decode("ascii").strip() == hashlib.sha256(payload).hexdigest(), (
                        f"worker {worker_idx} POST SHA-256 mismatch"
                    )
                else:
                    expected = deterministic_bytes(size)
                    st, _, body = Socks5Client.socks5_http_get(
                        "127.0.0.1",
                        socks_port,
                        "127.0.0.1",
                        http_srv.port,
                        path=f"/bytes/{size}",
                        timeout=25.0,
                    )
                    assert st == 200, f"worker {worker_idx} GET HTTP {st}"
                    assert hashlib.sha256(body).digest() == hashlib.sha256(expected).digest(), (
                        f"worker {worker_idx} GET SHA-256 mismatch ({len(body)} vs {size})"
                    )
            except Exception as exc:
                with err_lock:
                    errors.append(f"http[{worker_idx}]: {type(exc).__name__}: {exc}")

        def probe_worker(probe_idx: int) -> None:
            kind = probe_idx % 3
            try:
                barrier.wait()
                if kind == 0:
                    res = MaskedTcpProbe.send_and_probe(
                        "127.0.0.1",
                        srv_port,
                        payload=os.urandom(WIRE_PRELUDE_LEN + 32),
                        timeout=6.0,
                        wait_for_close=True,
                    )
                elif kind == 1:
                    res = MaskedTcpProbe.probe_masked(
                        "127.0.0.1",
                        srv_port,
                        keys=keys,
                        identity=0x40100 + probe_idx,
                        counter=1,
                        plaintext_after_prelude=b"\x63" * 64,
                        timeout=6.0,
                        wait_for_close=True,
                    )
                else:
                    res = MaskedTcpProbe.probe_masked(
                        "127.0.0.1",
                        srv_port,
                        keys=keys,
                        identity=0x40100 + probe_idx,
                        counter=2,
                        plaintext_after_prelude=build_tls12_client_hello(),
                        timeout=6.0,
                        wait_for_close=True,
                    )
                assert res.raw_received == b"", (
                    f"probe {probe_idx} leaked {len(res.raw_received)}B"
                )
                assert res.close_kind == CloseKind.RST, (
                    f"probe {probe_idx} expected RST, got {res.close_kind}"
                )
            except Exception as exc:
                with err_lock:
                    errors.append(f"probe[{probe_idx}]: {type(exc).__name__}: {exc}")

        threads: List[threading.Thread] = []
        for i in range(18):
            threads.append(threading.Thread(target=http_worker, args=(i,), daemon=True))
        for j in range(30):
            threads.append(threading.Thread(target=probe_worker, args=(j,), daemon=True))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=35.0)
            assert not t.is_alive(), "worker thread timed out in t4_01"

        assert not errors, "t4_01 errors:\n" + "\n".join(errors)
        ready_status, _ = http_get(f"127.0.0.1:{srv_obs}", path="/readyz")
        assert ready_status == 200


# ---------------------------------------------------------------------------
# T4-02: Concurrent Masked QUIC + TCP Mix under Invalid UDP Batch Flood
# ---------------------------------------------------------------------------

def t4_02_concurrent_masked_quic_and_tcp_under_udp_batch(ctx: TestContext) -> None:
    """Masked TCP & masked QUIC clients run concurrent HTTP + UDP echo bursts alongside 1,000 invalid UDP datagrams."""
    with ctx.workspace("t4_02") as ws:
        certs = ws.generate_certs()
        secret = make_secret()
        wrong_keys = derive_mask_keys("k1", make_secret())

        http_srv = ws.enter(LocalHttpServer())
        udp_echo = ws.enter(LocalUdpEchoServer())
        policy_toml = ws.write_secret(
            "policy.toml", allow_loopback_policy(ports=[http_srv.port, udp_echo.port])
        )
        tcp_port = free_tcp_port()
        udp_port = free_udp_port()
        srv_obs = free_tcp_port()

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                quic_listen=f"127.0.0.1:{udp_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[{"key_id": "k1", "secret": secret}],
                limits={"max_sessions": 32, "max_streams": 64, "auth_rate_limit_failures": 0},
                masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        tcp_socks = free_tcp_port()
        tcp_obs = free_tcp_port()
        tcp_cli = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                ws.write_secret(
                    "cli_tcp.toml",
                    build_client_toml(
                        server_addr=f"tls://127.0.0.1:{tcp_port}",
                        ca_cert_path=certs.ca_cert,
                        key_id="k1",
                        secret=secret,
                        observability_listen=f"127.0.0.1:{tcp_obs}",
                        extra={"max_carrier_sessions": 2},
                        masking={"enabled": True, "prelude_policy": "fade"},
                    ),
                ),
                socks_listen=f"127.0.0.1:{tcp_socks}",
                observability_listen=f"127.0.0.1:{tcp_obs}",
            )
        )
        tcp_cli.wait_ready(require_session=True, timeout=15.0)

        quic_socks = free_tcp_port()
        quic_obs = free_tcp_port()
        quic_cli = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                ws.write_secret(
                    "cli_quic.toml",
                    build_client_toml(
                        server_addr=f"quic://127.0.0.1:{udp_port}",
                        ca_cert_path=certs.ca_cert,
                        key_id="k1",
                        secret=secret,
                        observability_listen=f"127.0.0.1:{quic_obs}",
                        extra={"max_carrier_sessions": 2},
                        masking={"enabled": False, "quic": True},
                    ),
                ),
                socks_listen=f"127.0.0.1:{quic_socks}",
                observability_listen=f"127.0.0.1:{quic_obs}",
            )
        )
        quic_cli.wait_ready(require_session=True, timeout=15.0)

        # 6 HTTP TCP + 6 HTTP QUIC + 2 UDP bursts + 1 flood = 15 workers
        barrier = threading.Barrier(15, timeout=20.0)
        errors: List[str] = []
        err_lock = threading.Lock()
        http_sizes = [32768, 65536, 131072, 262144, 98304, 196608]

        def run_http(label: str, socks_port: int, idx: int) -> None:
            sz = http_sizes[idx % len(http_sizes)]
            try:
                barrier.wait()
                if idx % 2 == 0:
                    exp = deterministic_bytes(sz)
                    st, _, body = Socks5Client.socks5_http_get(
                        "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, path=f"/bytes/{sz}"
                    )
                    assert st == 200 and hashlib.sha256(body).digest() == hashlib.sha256(exp).digest()
                else:
                    payload = deterministic_bytes(sz, seed=0x4020 + idx)
                    st, _, body = Socks5Client.socks5_http_post(
                        "127.0.0.1",
                        socks_port,
                        "127.0.0.1",
                        http_srv.port,
                        path="/sha256",
                        body=payload,
                    )
                    assert st == 200 and body.decode("ascii").strip() == hashlib.sha256(payload).hexdigest()
            except Exception as exc:
                with err_lock:
                    errors.append(f"{label}-http[{idx}]: {type(exc).__name__}: {exc}")

        def run_udp_burst(label: str, socks_port: int, seed_base: int) -> None:
            try:
                barrier.wait()
                payloads = [deterministic_bytes(512 + i * 80, seed=seed_base + i) for i in range(10)]
                resps = Socks5Client.socks5_udp_exchange(
                    "127.0.0.1", socks_port, "127.0.0.1", udp_echo.port, payloads, timeout=15.0
                )
                assert resps == payloads, f"{label} UDP echo payload mismatch"
            except Exception as exc:
                with err_lock:
                    errors.append(f"{label}-udp: {type(exc).__name__}: {exc}")

        def run_udp_flood() -> None:
            try:
                with QuicProbeSocket("127.0.0.1", udp_port) as qp:
                    barrier.wait()
                    for i in range(1000):
                        mod = i % 4
                        if mod == 0:
                            qp.send_raw(b"")
                        elif mod == 1:
                            qp.send_raw(os.urandom(12))
                        elif mod == 2:
                            qp.send_masked(
                                wrong_keys, build_quic_initial_probe(version=QUIC_V1, size=256)
                            )
                        else:
                            qp.send_raw(build_quic_initial_probe(version=0, size=1200))
                    replies = qp.recv_packets(timeout=0.5)
                    assert replies == [], (
                        f"expected 0 UDP replies to invalid flood socket, got {len(replies)}"
                    )
            except Exception as exc:
                with err_lock:
                    errors.append(f"udp-flood: {type(exc).__name__}: {exc}")

        threads: List[threading.Thread] = []
        for i in range(6):
            threads.append(threading.Thread(target=run_http, args=("tcp", tcp_socks, i), daemon=True))
            threads.append(threading.Thread(target=run_http, args=("quic", quic_socks, i), daemon=True))
        threads.append(threading.Thread(target=run_udp_burst, args=("tcp", tcp_socks, 100), daemon=True))
        threads.append(threading.Thread(target=run_udp_burst, args=("quic", quic_socks, 200), daemon=True))
        threads.append(threading.Thread(target=run_udp_flood, daemon=True))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=35.0)
            assert not t.is_alive(), "worker thread timed out in t4_02"

        assert not errors, "t4_02 errors:\n" + "\n".join(errors)
        ready_status, _ = http_get(f"127.0.0.1:{srv_obs}", path="/readyz")
        assert ready_status == 200


# ---------------------------------------------------------------------------
# T4-03: Live SIGHUP Cert & Key Rotation Under Active Masked Load
# ---------------------------------------------------------------------------

def t4_03_live_sighup_cert_and_key_rotation_under_load(ctx: TestContext) -> None:
    """Active /slow masked TCP SOCKS5 stream survives SIGHUP cert+credential rotation while new k2 client (new CA) succeeds."""
    with ctx.workspace("t4_03") as ws:
        certs1 = ws.generate_certs(prefix="rot1")
        certs2 = ws.generate_certs(prefix="rot2")
        sec1 = make_secret()
        sec2 = make_secret()

        http_srv = ws.enter(LocalHttpServer())
        policy_toml = ws.write_secret("policy.toml", allow_loopback_policy(ports=[http_srv.port]))
        srv_port = free_tcp_port()
        srv_obs = free_tcp_port()

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{srv_port}",
                cert_path=certs1.cert,
                key_path=certs1.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[{"key_id": "k1", "secret": sec1}],
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        c1_socks = free_tcp_port()
        c1_obs = free_tcp_port()
        c1_toml = ws.write_secret(
            "client1.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{srv_port}",
                ca_cert_path=certs1.ca_cert,
                key_id="k1",
                secret=sec1,
                observability_listen=f"127.0.0.1:{c1_obs}",
                extra={"max_carrier_sessions": 1},
                masking={"enabled": True, "prelude_policy": "fade"},
            ),
        )
        cli1 = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                c1_toml,
                socks_listen=f"127.0.0.1:{c1_socks}",
                observability_listen=f"127.0.0.1:{c1_obs}",
            )
        )
        cli1.wait_ready(require_session=True, timeout=15.0)

        total_slow = 524288
        expected_slow = deterministic_bytes(total_slow)
        in_flight_started = threading.Event()
        slow_result: Dict[str, Any] = {}

        def slow_reader() -> None:
            sock = Socks5Client.socks5_connect("127.0.0.1", c1_socks, "127.0.0.1", http_srv.port)
            try:
                sock.settimeout(20.0)
                req = (
                    f"GET /slow?bytes={total_slow}&chunk=8192&delay_ms=25 HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{http_srv.port}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                sock.sendall(req)
                buf = bytearray()
                hdr_end = -1
                while True:
                    chunk = sock.recv(16384)
                    if not chunk:
                        break
                    buf += chunk
                    if hdr_end < 0:
                        hdr_end = buf.find(b"\r\n\r\n")
                    if (
                        not in_flight_started.is_set()
                        and hdr_end >= 0
                        and len(buf) - (hdr_end + 4) >= 16384
                    ):
                        in_flight_started.set()
                slow_result["hdr_end"] = hdr_end
                slow_result["raw"] = bytes(buf)
            except Exception as exc:
                slow_result["error"] = exc
                in_flight_started.set()
            finally:
                sock.close()

        slow_thread = threading.Thread(target=slow_reader, daemon=True)
        slow_thread.start()
        assert in_flight_started.wait(timeout=10.0), "timed out waiting for /slow initial bytes"
        assert "error" not in slow_result, f"/slow reader failed early: {slow_result.get('error')}"

        # Rotate both TLS cert/key (certs1 -> certs2) and credentials (add k2) via SIGHUP
        before_gen = srv.metric("uncrowned_king_server_security_generation")
        ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{srv_port}",
                cert_path=certs2.cert,
                key_path=certs2.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[
                    {"key_id": "k1", "secret": sec1},
                    {"key_id": "k2", "secret": sec2},
                ],
                masking={"enabled": True},
            ),
        )
        srv.send_sighup()
        new_gen = srv.wait_for_metric(
            "uncrowned_king_server_security_generation",
            lambda v: v > before_gen,
            timeout=10.0,
        )
        assert new_gen > before_gen
        assert srv.metric("uncrowned_king_server_config_reload_failures_total") == 0

        # New client using CA2 + k2 connects after SIGHUP and transfers HTTP cleanly
        c2_socks = free_tcp_port()
        c2_obs = free_tcp_port()
        c2_toml = ws.write_secret(
            "client2.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{srv_port}",
                ca_cert_path=certs2.ca_cert,
                key_id="k2",
                secret=sec2,
                observability_listen=f"127.0.0.1:{c2_obs}",
                extra={"max_carrier_sessions": 1},
                masking={"enabled": True, "prelude_policy": "full8"},
            ),
        )
        cli2 = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                c2_toml,
                socks_listen=f"127.0.0.1:{c2_socks}",
                observability_listen=f"127.0.0.1:{c2_obs}",
            )
        )
        cli2.wait_ready(require_session=True, timeout=15.0)
        st2, _, b2 = Socks5Client.socks5_http_get(
            "127.0.0.1", c2_socks, "127.0.0.1", http_srv.port, path="/bytes/131072"
        )
        assert st2 == 200 and hashlib.sha256(b2).digest() == hashlib.sha256(
            deterministic_bytes(131072)
        ).digest()

        # Verify in-flight /slow stream on client1 completed with 100% SHA-256 parity
        slow_thread.join(timeout=20.0)
        assert not slow_thread.is_alive(), "client1 /slow reader timed out"
        assert "error" not in slow_result, f"/slow reader failed: {slow_result.get('error')}"
        hdr_end = slow_result["hdr_end"]
        raw = slow_result["raw"]
        assert hdr_end >= 0
        status_code = int(raw[:hdr_end].decode("iso-8859-1").split("\r\n", 1)[0].split(" ", 2)[1])
        body = raw[hdr_end + 4 :]
        assert status_code == 200 and len(body) == total_slow
        assert hashlib.sha256(body).digest() == hashlib.sha256(expected_slow).digest()


# ---------------------------------------------------------------------------
# T4-04: Distributed Pre-Auth Slowloris + Bad-Hello Storm across Sources
# ---------------------------------------------------------------------------

def t4_04_multi_source_pre_auth_saturation_with_legit_client(ctx: TestContext) -> None:
    """Attacker sources (::1, fe80::1%lo0) saturate per_source=4 (global=16) while legit 127.0.0.1 uk-client relays continuously and /readyz stays 200."""
    sources = discover_loopback_sources()
    assert "127.0.0.1" in sources and "::1" in sources, (
        f"requires IPv4 & IPv6 loopback sources, discovered={sources}"
    )
    attack_sources = [s for s in ("::1", "fe80::1%lo0") if s in sources]

    with ctx.workspace("t4_04") as ws:
        certs = ws.generate_certs()
        secret = make_secret()

        http_srv = ws.enter(LocalHttpServer())
        policy_toml = ws.write_secret("policy.toml", allow_loopback_policy(ports=[http_srv.port]))
        srv_port = free_tcp_port("::")
        srv_obs = free_tcp_port()

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"[::]:{srv_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[{"key_id": "k1", "secret": secret}],
                limits={
                    "max_pre_auth_connections": 16,
                    "max_pre_auth_per_source": 4,
                    "handshake_timeout_seconds": 10,
                    "auth_rate_limit_failures": 10,
                },
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        # Legitimate 127.0.0.1 client
        cli_socks = free_tcp_port()
        cli_obs = free_tcp_port()
        cli_toml = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{srv_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{cli_obs}",
                extra={"max_carrier_sessions": 2},
                masking={"enabled": True, "prelude_policy": "fade"},
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                cli_toml,
                socks_listen=f"127.0.0.1:{cli_socks}",
                observability_listen=f"127.0.0.1:{cli_obs}",
            )
        )
        cli.wait_ready(require_session=True, timeout=15.0)

        held_attack: List[socket.socket] = []
        try:
            before_acc = srv.metric("uncrowned_king_server_accepted_connections_total")
            for src in attack_sources:
                for _ in range(4):
                    held_attack.append(
                        MaskedTcpProbe.open_socket(src, srv_port, source_addr=src, timeout=5.0)
                    )
            srv.wait_for_metric(
                "uncrowned_king_server_accepted_connections_total",
                lambda v: v >= before_acc + 4 * len(attack_sources),
                timeout=5.0,
            )

            # Excess probes from each saturated attacker source must close immediately via RST
            for src in attack_sources:
                for _ in range(3):
                    t0 = time.monotonic()
                    s: Optional[socket.socket] = None
                    try:
                        s = MaskedTcpProbe.open_socket(src, srv_port, source_addr=src, timeout=3.0)
                        # Send invalid bytes; pre-admission drops immediately
                        try:
                            s.sendall(b"\x63" * 32)
                        except OSError:
                            pass
                        res = read_until_close(s, timeout=1.5)
                    except OSError as exc:
                        if exc.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE):
                            res = ProbeResult(
                                received=b"",
                                raw_received=b"",
                                close_kind=CloseKind.RST,
                                elapsed_s=time.monotonic() - t0,
                                error=str(exc),
                            )
                        else:
                            raise
                    finally:
                        if s is not None:
                            s.close()
                    assert (
                        res.close_kind == CloseKind.RST
                        and res.raw_received == b""
                        and res.elapsed_s < 0.8
                    ), (
                        f"source {src} excess socket expected immediate silent RST (0B), got "
                        f"{res.close_kind} ({len(res.raw_received)}B) in {res.elapsed_s:.3f}s"
                    )

            for hs in held_attack:
                assert check_socket_closed(hs, timeout=0.05) == CloseKind.OPEN

            # Legitimate 127.0.0.1 client relays continuously & new 127.0.0.1 handshake succeeds
            for i in range(6):
                sz = 16384 * (i + 1)
                exp = deterministic_bytes(sz)
                st, _, body = Socks5Client.socks5_http_get(
                    "127.0.0.1", cli_socks, "127.0.0.1", http_srv.port, path=f"/bytes/{sz}"
                )
                assert st == 200 and hashlib.sha256(body).digest() == hashlib.sha256(exp).digest()

            hs_new = run_client_handshake(ctx.client_bin, cli_toml, timeout=10.0)
            assert hs_new.returncode == 0, (
                f"new 127.0.0.1 handshake failed while attacker sources saturated: {hs_new.stderr}\n{hs_new.stdout}"
            )
            ready_status, _ = http_get(f"127.0.0.1:{srv_obs}", path="/readyz")
            assert ready_status == 200
        finally:
            _close_sockets(held_attack)


# ---------------------------------------------------------------------------
# T4-05: Pool Saturation (max_carrier_sessions=2) & Egress Policy Enforcement
# ---------------------------------------------------------------------------

def t4_05_pool_saturation_and_egress_policy_enforcement(ctx: TestContext) -> None:
    """max_carrier_sessions=2 multiplexes 12 concurrent streams (8 allowed HTTP + 4 policy-denied incl. 169.254.169.254 & disallowed port -> SOCKS5 0x02)."""
    with ctx.workspace("t4_05") as ws:
        certs = ws.generate_certs()
        secret = make_secret()

        allowed_http = ws.enter(LocalHttpServer())
        denied_http = ws.enter(LocalHttpServer())
        policy_toml = ws.write_secret(
            "policy.toml",
            allow_loopback_policy(ports=[allowed_http.port], allow_v6=False),
        )
        srv_port = free_tcp_port()
        srv_obs = free_tcp_port()
        cli_obs = free_tcp_port()
        socks_port = free_tcp_port()

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{srv_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[{"key_id": "k1", "secret": secret}],
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        cli_toml = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{srv_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{cli_obs}",
                extra={"max_carrier_sessions": 2},
                masking={"enabled": True, "prelude_policy": "fade"},
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                cli_toml,
                socks_listen=f"127.0.0.1:{socks_port}",
                observability_listen=f"127.0.0.1:{cli_obs}",
            )
        )
        cli.wait_ready(require_session=True, timeout=15.0)

        allowed_sizes = [4096, 16384, 65536, 131072, 8192, 32768, 70000, 98304]
        denied_targets: List[Tuple[str, int]] = [
            ("169.254.169.254", 80),
            ("169.254.169.254", 80),
            ("127.0.0.1", denied_http.port),
            ("127.0.0.1", denied_http.port),
        ]

        barrier = threading.Barrier(12, timeout=20.0)
        errors: List[str] = []
        err_lock = threading.Lock()
        denied_codes: List[int] = []

        def allowed_worker(idx: int) -> None:
            sz = allowed_sizes[idx]
            try:
                barrier.wait()
                exp = deterministic_bytes(sz)
                st, _, body = Socks5Client.socks5_http_get(
                    "127.0.0.1",
                    socks_port,
                    "127.0.0.1",
                    allowed_http.port,
                    path=f"/bytes/{sz}",
                    timeout=20.0,
                )
                assert st == 200, f"allowed[{idx}] HTTP {st}"
                assert hashlib.sha256(body).digest() == hashlib.sha256(exp).digest(), (
                    f"allowed[{idx}] SHA-256 mismatch"
                )
            except Exception as exc:
                with err_lock:
                    errors.append(f"allowed[{idx}]: {type(exc).__name__}: {exc}")

        def denied_worker(idx: int) -> None:
            host, port = denied_targets[idx]
            try:
                barrier.wait()
                try:
                    sock = Socks5Client.socks5_connect("127.0.0.1", socks_port, host, port, timeout=15.0)
                    sock.close()
                    raise AssertionError(f"expected SOCKS5 0x02 denial for {host}:{port}, got success")
                except Socks5Error as exc:
                    assert exc.reply_code == 0x02, (
                        f"expected SOCKS5 reply 0x02 (NotAllowed) for {host}:{port}, got 0x{exc.reply_code:02x}"
                    )
                    with err_lock:
                        denied_codes.append(exc.reply_code)
            except Exception as exc:
                with err_lock:
                    errors.append(f"denied[{idx}]: {type(exc).__name__}: {exc}")

        threads: List[threading.Thread] = []
        for i in range(8):
            threads.append(threading.Thread(target=allowed_worker, args=(i,), daemon=True))
        for j in range(4):
            threads.append(threading.Thread(target=denied_worker, args=(j,), daemon=True))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)
            assert not t.is_alive(), "worker thread timed out in t4_05"

        assert not errors, "t4_05 errors:\n" + "\n".join(errors)
        assert denied_codes == [0x02, 0x02, 0x02, 0x02]

        policy_denials = srv.wait_for_metric(
            "uncrowned_king_server_flow_open_failures_total",
            lambda v: v >= 4,
            labels={"protocol": "tcp", "reason": "policy_denied"},
            timeout=5.0,
        )
        assert policy_denials >= 4
        assert cli.metric("uncrowned_king_client_active_sessions") >= 1, (
            "carrier sessions should remain active after policy denials"
        )

        # Follow-up allowed transfer confirms pool remains completely healthy
        st_post, _, body_post = Socks5Client.socks5_http_get(
            "127.0.0.1", socks_port, "127.0.0.1", allowed_http.port, path="/bytes/16384"
        )
        assert st_post == 200 and body_post == deterministic_bytes(16384)


# ---------------------------------------------------------------------------
# T4-06: Graceful SIGTERM Shutdown Drain Under Active Masked Workload
# ---------------------------------------------------------------------------

def t4_06_graceful_shutdown_under_active_masked_workload(ctx: TestContext) -> None:
    """3 active /slow masked SOCKS5 streams (2 MiB + 2x 256 KiB) finish cleanly with 100% SHA-256 parity on server SIGTERM (exit 0)."""
    with ctx.workspace("t4_06") as ws:
        certs = ws.generate_certs()
        secret = make_secret()

        http_srv = ws.enter(LocalHttpServer())
        policy_toml = ws.write_secret("policy.toml", allow_loopback_policy(ports=[http_srv.port]))
        srv_port = free_tcp_port()
        srv_obs = free_tcp_port()
        cli_obs = free_tcp_port()
        socks_port = free_tcp_port()

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{srv_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[{"key_id": "k1", "secret": secret}],
                limits={"shutdown_timeout_seconds": 10},
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        cli_toml = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{srv_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{cli_obs}",
                extra={"max_carrier_sessions": 2},
                masking={"enabled": True, "prelude_policy": "fade"},
            ),
        )
        cli = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                cli_toml,
                socks_listen=f"127.0.0.1:{socks_port}",
                observability_listen=f"127.0.0.1:{cli_obs}",
            )
        )
        cli.wait_ready(require_session=True, timeout=15.0)

        stream_specs = [
            (2 * 1024 * 1024, 32768, 15, 65536),
            (256 * 1024, 16384, 30, 16384),
            (256 * 1024, 16384, 30, 16384),
        ]
        started_events = [threading.Event() for _ in stream_specs]
        results: List[Dict[str, Any]] = [{} for _ in stream_specs]

        def stream_worker(idx: int) -> None:
            total, chunk_sz, delay_ms, min_initial = stream_specs[idx]
            sock = Socks5Client.socks5_connect("127.0.0.1", socks_port, "127.0.0.1", http_srv.port)
            try:
                sock.settimeout(25.0)
                req = (
                    f"GET /slow?bytes={total}&chunk={chunk_sz}&delay_ms={delay_ms} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{http_srv.port}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                sock.sendall(req)
                buf = bytearray()
                hdr_end = -1
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if hdr_end < 0:
                        hdr_end = buf.find(b"\r\n\r\n")
                    if (
                        not started_events[idx].is_set()
                        and hdr_end >= 0
                        and len(buf) - (hdr_end + 4) >= min_initial
                    ):
                        started_events[idx].set()
                results[idx]["hdr_end"] = hdr_end
                results[idx]["raw"] = bytes(buf)
            except Exception as exc:
                results[idx]["error"] = exc
                started_events[idx].set()
            finally:
                sock.close()

        threads = [
            threading.Thread(target=stream_worker, args=(i,), daemon=True)
            for i in range(len(stream_specs))
        ]
        for t in threads:
            t.start()

        for i, ev in enumerate(started_events):
            assert ev.wait(timeout=12.0), f"stream {i} did not start receiving /slow bytes"
            assert "error" not in results[i], (
                f"stream {i} failed before SIGTERM: {results[i].get('error')}"
            )

        # All 3 masked streams are actively in-flight; send SIGTERM
        srv.send_sigterm()

        for i, t in enumerate(threads):
            t.join(timeout=25.0)
            assert not t.is_alive(), f"stream {i} timed out during graceful shutdown"
            assert "error" not in results[i], (
                f"stream {i} errored during drain: {results[i].get('error')}"
            )
            hdr_end = results[i]["hdr_end"]
            raw = results[i]["raw"]
            assert hdr_end >= 0
            status_code = int(
                raw[:hdr_end].decode("iso-8859-1").split("\r\n", 1)[0].split(" ", 2)[1]
            )
            body = raw[hdr_end + 4 :]
            expected_len = stream_specs[i][0]
            assert status_code == 200, f"stream {i} status {status_code}"
            assert len(body) == expected_len, (
                f"stream {i} truncated: got {len(body)}B, expected {expected_len}B"
            )
            assert (
                hashlib.sha256(body).digest()
                == hashlib.sha256(deterministic_bytes(expected_len)).digest()
            ), f"stream {i} SHA-256 mismatch"

        rc = srv.wait_exit(timeout=15.0)
        assert rc == 0, f"expected uk-server clean exit 0 on SIGTERM drain, got {rc}"


def collect_tests(_ctx: TestContext) -> List[E2ETestCase]:
    return [
        E2ETestCase(
            name="t4_01_concurrent_multi_client_masked_tcp_under_probes",
            tier=4,
            requirement="R1+R4+R5+R6",
            fn=t4_01_concurrent_multi_client_masked_tcp_under_probes,
            description="3 masked TCP clients (fade/full8/low7) run 18 concurrent HTTP transfers alongside 30 silent-reject probes.",
        ),
        E2ETestCase(
            name="t4_02_concurrent_masked_quic_and_tcp_under_udp_batch",
            tier=4,
            requirement="R3+R5+R6",
            fn=t4_02_concurrent_masked_quic_and_tcp_under_udp_batch,
            description="Masked TCP + masked QUIC clients run concurrent HTTP + UDP bursts alongside 1,000 invalid UDP datagrams.",
        ),
        E2ETestCase(
            name="t4_03_live_sighup_cert_and_key_rotation_under_load",
            tier=4,
            requirement="R4+R5+R6",
            fn=t4_03_live_sighup_cert_and_key_rotation_under_load,
            description="Active /slow masked stream survives SIGHUP TLS cert + key rotation while new k2 client connects.",
        ),
        E2ETestCase(
            name="t4_04_multi_source_pre_auth_saturation_with_legit_client",
            tier=4,
            requirement="R1+R2+R6",
            fn=t4_04_multi_source_pre_auth_saturation_with_legit_client,
            description="Attacker sources saturate per_source=4 while legit 127.0.0.1 client continues relaying and /readyz stays 200.",
        ),
        E2ETestCase(
            name="t4_05_pool_saturation_and_egress_policy_enforcement",
            tier=4,
            requirement="R4+R5+R6",
            fn=t4_05_pool_saturation_and_egress_policy_enforcement,
            description="max_carrier_sessions=2 multiplexes 8 allowed HTTP streams and 4 policy-denied targets (SOCKS5 0x02).",
        ),
        E2ETestCase(
            name="t4_06_graceful_shutdown_under_active_masked_workload",
            tier=4,
            requirement="R4+R5",
            fn=t4_06_graceful_shutdown_under_active_masked_workload,
            description="3 active /slow masked streams finish cleanly with 100% SHA-256 parity on server SIGTERM.",
        ),
    ]
