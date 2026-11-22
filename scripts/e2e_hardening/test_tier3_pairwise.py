"""Tier 3: Pairwise Combinatorial E2E Tests (R1–R6) for Uncrowned King.

Covers 10 cross-feature interaction tests:
  t3_01: R1 x R4 — Delayed corrupt ClientHello within shared deadline (RST, 0B, counter preserved)
  t3_02: R1 x R2 — Per-source pre-admission saturation + concurrent bad ClientHello on 2nd source
  t3_03: R1 x R5 — Coalesced client handshake vs racing raw replay rejection
  t3_04: R2 x R3 — Shared PreAdmissionLimiter across TCP pre-auth holds & masked QUIC
  t3_05: R2 x R6 — Split mode (TCP unmasked, QUIC masked) + timeout=0 + pre-admission limit
  t3_06: R3 x R6 — Masked QUIC retains masking & MTU across SIGHUP TLS cert rotation
  t3_07: R4 x R5 — Coalesced masked TCP client active stream completes cleanly on server SIGTERM
  t3_08: R1 x R6 — handshake_timeout_seconds=0 masking fallback with corrupt ClientHello
  t3_09: R5 x R6 — SIGHUP credential rotation + coalesced new-key client via proxy
  t3_10: R3 x R5 — Blackholed QUIC failover to coalesced masked TCP + curl transfer
"""

import hashlib
import shutil
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple

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
        format_host_port,
        free_tcp_port,
        free_udp_port,
        make_secret,
        run_client_handshake,
        run_config_check,
    )
    from .uk_wire import (
        QUIC_V1,
        WIRE_PRELUDE_LEN,
        ChaCha20Stream,
        CloseKind,
        MaskedTcpProbe,
        QuicProbeSocket,
        Socks5Client,
        TransparentFirstSegmentProxy,
        UdpObserverProxy,
        build_quic_initial_probe,
        build_tls13_client_hello,
        check_socket_closed,
        derive_mask_keys,
        encode_prelude,
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
        format_host_port,
        free_tcp_port,
        free_udp_port,
        make_secret,
        run_client_handshake,
        run_config_check,
    )
    from uk_wire import (
        QUIC_V1,
        WIRE_PRELUDE_LEN,
        ChaCha20Stream,
        CloseKind,
        MaskedTcpProbe,
        QuicProbeSocket,
        Socks5Client,
        TransparentFirstSegmentProxy,
        UdpObserverProxy,
        build_quic_initial_probe,
        build_tls13_client_hello,
        check_socket_closed,
        derive_mask_keys,
        encode_prelude,
        read_until_close,
    )


def _assert_server_hello(received: bytes, context: str) -> None:
    assert len(received) >= 6, f"{context}: expected ServerHello bytes, got {len(received)}B"
    assert received[0] == 0x16, (
        f"{context}: expected TLS Handshake record 0x16, got 0x{received[0]:02x}"
    )
    assert received[5] == 0x02, (
        f"{context}: expected TLS ServerHello handshake type 0x02, got 0x{received[5]:02x}"
    )


def _close_sockets(sockets: List[socket.socket]) -> None:
    for s in sockets:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# T3-01: R1 x R4 — Delayed corrupt ClientHello within shared deadline
# ---------------------------------------------------------------------------

def t3_01_r1_r4_delayed_corrupt_hello_shared_deadline(ctx: TestContext) -> None:
    """Valid prelude + corrupt ClientHello delayed 1.2s into 2s deadline closes via RST within shared budget without burning counter."""
    with ctx.workspace("t3_01") as ws:
        certs = ws.generate_certs()
        secret = make_secret()
        keys = derive_mask_keys("k1", secret)
        tcp_port = free_tcp_port()
        obs_port = free_tcp_port()
        obs_addr = f"127.0.0.1:{obs_port}"

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                observability_listen=obs_addr,
                credentials=[{"key_id": "k1", "secret": secret}],
                limits={
                    "handshake_timeout_seconds": 2,
                    "auth_rate_limit_failures": 10,
                },
                masking={"enabled": True},
            ),
        )

        srv = ws.enter(UkServerProcess(ctx.server_bin, srv_toml, observability_listen=obs_addr))
        srv.wait_ready()

        identity = 0x30101
        counter = 1
        prelude_wire, nonce = encode_prelude(keys, identity=identity, counter=counter)
        c2s = ChaCha20Stream(keys.tcp_c2s, nonce)

        t0 = time.monotonic()
        sock = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=5.0)
        try:
            sock.sendall(prelude_wire)
            # Verify server stays open during 1.2s delay before ClientHello arrives
            mid_state = check_socket_closed(sock, timeout=1.2)
            assert mid_state == CloseKind.OPEN, (
                f"expected socket to remain OPEN at 1.2s within 2s deadline, got {mid_state}"
            )
            corrupt_hello = b"\x63" * 64
            sock.sendall(c2s.apply(corrupt_hello))
            res = read_until_close(sock, timeout=4.0, start_time=t0)
        finally:
            sock.close()

        assert res.raw_received == b"", (
            f"expected 0 response bytes on corrupt ClientHello, got {len(res.raw_received)}B"
        )
        assert res.close_kind == CloseKind.RST, (
            f"expected RST (SO_LINGER=0), got {res.close_kind}"
        )
        assert 1.2 <= res.elapsed_s <= 2.8, (
            f"expected shared 2s deadline close (not 1.2s+2s=3.2s), elapsed={res.elapsed_s:.3f}s"
        )

        # Counter must NOT be committed on corrupt ClientHello
        res2 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            keys=keys,
            identity=identity,
            counter=counter,
            plaintext_after_prelude=build_tls13_client_hello(),
            wait_for_close=False,
            timeout=5.0,
        )
        _assert_server_hello(res2.received, "t3_01 counter reuse after corrupt ClientHello")


# ---------------------------------------------------------------------------
# T3-02: R1 x R2 — Source saturation + concurrent bad ClientHello on 2nd source
# ---------------------------------------------------------------------------

def t3_02_r1_r2_source_saturation_with_concurrent_bad_hello(ctx: TestContext) -> None:
    """Source 1 saturates max_pre_auth_per_source (immediate RST) while source 2 triggers R1 silent corrupt-hello without burning counter."""
    sources = discover_loopback_sources()
    assert "127.0.0.1" in sources and "::1" in sources, (
        f"requires IPv4 & IPv6 loopback sources, discovered={sources}"
    )

    with ctx.workspace("t3_02") as ws:
        certs = ws.generate_certs()
        secret = make_secret()
        keys = derive_mask_keys("k1", secret)
        tcp_port = free_tcp_port("::")
        obs_port = free_tcp_port()
        obs_addr = f"127.0.0.1:{obs_port}"

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"[::]:{tcp_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                observability_listen=obs_addr,
                credentials=[{"key_id": "k1", "secret": secret}],
                limits={
                    "max_pre_auth_connections": 16,
                    "max_pre_auth_per_source": 2,
                    "handshake_timeout_seconds": 2,
                    "auth_rate_limit_failures": 10,
                },
                masking={"enabled": True},
            ),
        )

        srv = ws.enter(UkServerProcess(ctx.server_bin, srv_toml, observability_listen=obs_addr))
        srv.wait_ready()

        held_v6: List[socket.socket] = []
        try:
            for _ in range(2):
                held_v6.append(
                    MaskedTcpProbe.open_socket("::1", tcp_port, source_addr="::1", timeout=5.0)
                )
            # Deterministically wait for the 2 held connections to enter accept/pre-admission
            srv.wait_for_metric(
                "uncrowned_king_server_accepted_connections_total",
                lambda v: v >= 2,
                timeout=5.0,
            )

            # 3rd socket from ::1 must be dropped immediately by PreAdmissionLimiter
            over_sock = MaskedTcpProbe.open_socket("::1", tcp_port, source_addr="::1", timeout=3.0)
            try:
                over_res = read_until_close(over_sock, timeout=1.5)
            finally:
                over_sock.close()
            assert over_res.close_kind == CloseKind.RST, (
                f"expected immediate RST on ::1 3rd pre-auth socket, got {over_res.close_kind}"
            )
            assert over_res.elapsed_s < 0.8, (
                f"expected immediate pre-admission drop, took {over_res.elapsed_s:.3f}s"
            )
            for idx, hs in enumerate(held_v6):
                assert check_socket_closed(hs, timeout=0.08) == CloseKind.OPEN, (
                    f"held ::1 socket #{idx} should remain OPEN"
                )

            # Concurrently from 127.0.0.1: trigger R1 corrupt ClientHello rejection
            identity = 0x30201
            counter = 9
            bad_res = MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                keys=keys,
                identity=identity,
                counter=counter,
                plaintext_after_prelude=b"\x16\x03\x01\x00\x20" + b"\xff" * 32,
                source_addr="127.0.0.1",
                timeout=5.0,
                wait_for_close=True,
            )
            assert bad_res.raw_received == b"", (
                f"expected 0 bytes on 127.0.0.1 bad hello, got {len(bad_res.raw_received)}B"
            )
            assert bad_res.close_kind == CloseKind.RST, (
                f"expected RST on bad hello, got {bad_res.close_kind}"
            )

            # Resend SAME (identity, counter) with valid TLS 1.3 ClientHello from 127.0.0.1
            ok_res = MaskedTcpProbe.probe_masked(
                "127.0.0.1",
                tcp_port,
                keys=keys,
                identity=identity,
                counter=counter,
                plaintext_after_prelude=build_tls13_client_hello(),
                source_addr="127.0.0.1",
                timeout=5.0,
                wait_for_close=False,
            )
            _assert_server_hello(ok_res.received, "t3_02 127.0.0.1 counter reuse")
        finally:
            _close_sockets(held_v6)


# ---------------------------------------------------------------------------
# T3-03: R1 x R5 — Coalesced client vs racing replay
# ---------------------------------------------------------------------------

def t3_03_r1_r5_coalesced_client_vs_racing_replay(ctx: TestContext) -> None:
    """uk-client coalesces >=76+5B first segment and succeeds while raw replay of captured prelude+ClientHello is rejected silently with RST."""
    with ctx.workspace("t3_03") as ws:
        certs = ws.generate_certs()
        secret = make_secret()
        keys = derive_mask_keys("k1", secret)

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
                limits={"handshake_timeout_seconds": 3, "auth_rate_limit_failures": 20},
                masking={"enabled": True},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        proxy = ws.enter(TransparentFirstSegmentProxy("127.0.0.1", srv_port))

        cli_toml = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{proxy.listen_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{cli_obs}",
                extra={"max_carrier_sessions": 1},
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

        first_seg = proxy.wait_for_first_segment(timeout=10.0)
        assert len(first_seg) >= WIRE_PRELUDE_LEN + 5, (
            f"expected coalesced first segment >= 81B, got {len(first_seg)}B"
        )

        # Replay the exact captured first segment (already committed by R1 after ClientHello)
        replay_res = MaskedTcpProbe.send_and_probe(
            "127.0.0.1",
            srv_port,
            payload=first_seg,
            timeout=5.0,
            wait_for_close=True,
        )
        assert replay_res.raw_received == b"", (
            f"expected 0 bytes on replayed coalesced segment, got {len(replay_res.raw_received)}B"
        )
        assert replay_res.close_kind == CloseKind.RST, (
            f"expected RST on replay, got {replay_res.close_kind}"
        )

        # Also test racing / duplicate (I, C) probe directly against server
        probe_id, probe_ctr = 0x30303, 7
        valid_hello = build_tls13_client_hello()
        first_probe = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            srv_port,
            keys=keys,
            identity=probe_id,
            counter=probe_ctr,
            plaintext_after_prelude=valid_hello,
            wait_for_close=False,
            timeout=5.0,
        )
        _assert_server_hello(first_probe.received, "t3_03 initial raw probe")

        dup_probe = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            srv_port,
            keys=keys,
            identity=probe_id,
            counter=probe_ctr,
            plaintext_after_prelude=valid_hello,
            wait_for_close=True,
            timeout=5.0,
        )
        assert dup_probe.raw_received == b"", "expected 0 bytes on duplicate raw replay"
        assert dup_probe.close_kind == CloseKind.RST, (
            f"expected RST on duplicate raw replay, got {dup_probe.close_kind}"
        )

        replays = srv.wait_for_metric(
            "uncrowned_king_server_mask_replay_rejects_total",
            lambda v: v >= 2,
            timeout=5.0,
        )
        assert replays >= 2

        # Existing coalesced client session must still relay cleanly
        expected = deterministic_bytes(65536)
        status, _hdrs, body = Socks5Client.socks5_http_get(
            "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, path="/bytes/65536"
        )
        assert status == 200 and hashlib.sha256(body).digest() == hashlib.sha256(expected).digest()


# ---------------------------------------------------------------------------
# T3-04: R2 x R3 — Shared PreAdmissionLimiter across TCP and masked QUIC
# ---------------------------------------------------------------------------

def t3_04_r2_r3_shared_pre_admission_tcp_and_quic(ctx: TestContext) -> None:
    """Holding max_pre_auth_connections=3 TCP pre-auth sockets causes masked QUIC to ignore() packets; releasing 1 slot lets QUIC uk-client succeed."""
    with ctx.workspace("t3_04") as ws:
        certs = ws.generate_certs()
        secret = make_secret()
        keys = derive_mask_keys("k1", secret)

        http_srv = ws.enter(LocalHttpServer())
        policy_toml = ws.write_secret("policy.toml", allow_loopback_policy(ports=[http_srv.port]))
        tcp_port = free_tcp_port()
        udp_port = free_udp_port()
        srv_obs = free_tcp_port()
        cli_obs = free_tcp_port()
        socks_port = free_tcp_port()

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
                limits={
                    "max_pre_auth_connections": 3,
                    "max_pre_auth_per_source": 3,
                    "handshake_timeout_seconds": 3,
                },
                masking={"enabled": True, "quic": True, "quic_key_id": "k1"},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        held_tcp: List[socket.socket] = []
        try:
            for _ in range(3):
                held_tcp.append(MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=5.0))

            srv.wait_for_metric(
                "uncrowned_king_server_accepted_connections_total",
                lambda v: v >= 3,
                timeout=5.0,
            )

            # With all 3 global pre-admission slots occupied, masked QUIC must emit 0 non-Retry packets (incoming.ignore())
            with UdpObserverProxy("127.0.0.1", udp_port) as proxy:
                sat_cli_toml = ws.write_secret(
                    "client_saturated.toml",
                    build_client_toml(
                        server_addr=f"quic://127.0.0.1:{proxy.port}",
                        ca_cert_path=certs.ca_cert,
                        key_id="k1",
                        secret=secret,
                        extra={"handshake_timeout_seconds": 1},
                        masking={"enabled": False, "quic": True},
                    ),
                )
                cp_sat = run_client_handshake(ctx.client_bin, sat_cli_toml, timeout=5.0)
                assert cp_sat.returncode != 0, (
                    "expected masked QUIC handshake to fail when PreAdmissionLimiter saturated"
                )
                assert len(proxy.c2s) >= 1, (
                    "expected saturated QUIC client to transmit UDP datagrams via proxy"
                )
                non_retry = proxy.non_retry_s2c_packets(keys)
                assert non_retry == [], (
                    f"expected 0 non-Retry UDP packets (incoming.ignore()) when PreAdmissionLimiter saturated, "
                    f"got {len(non_retry)}: {[p[:8].hex() for p in non_retry]}"
                )

            # Release 1 TCP pre-auth slot and wait for silent_drain RST so PreAdmissionPermit is freed
            popped_tcp = held_tcp.pop()
            try:
                popped_tcp.shutdown(socket.SHUT_WR)
                read_until_close(popped_tcp, timeout=5.0)
            finally:
                popped_tcp.close()

            cli_toml = ws.write_secret(
                "client.toml",
                build_client_toml(
                    server_addr=f"quic://127.0.0.1:{udp_port}",
                    ca_cert_path=certs.ca_cert,
                    key_id="k1",
                    secret=secret,
                    observability_listen=f"127.0.0.1:{cli_obs}",
                    extra={"max_carrier_sessions": 1, "handshake_timeout_seconds": 2},
                    masking={"enabled": False, "quic": True},
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

            expected = deterministic_bytes(65536)
            status, _hdrs, body = Socks5Client.socks5_http_get(
                "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, path="/bytes/65536"
            )
            assert status == 200
            assert hashlib.sha256(body).digest() == hashlib.sha256(expected).digest()
        finally:
            _close_sockets(held_tcp)


# ---------------------------------------------------------------------------
# T3-05: R2 x R6 — Split mode + zero timeout + pre-admission limit
# ---------------------------------------------------------------------------

def t3_05_r2_r6_split_mode_with_pre_admission_and_zero_timeout(ctx: TestContext) -> None:
    """Split mode (TCP unmasked, QUIC masked) + timeout=0 + max_pre_auth_per_source=2 allows both carriers and enforces pre-admission."""
    with ctx.workspace("t3_05") as ws:
        certs = ws.generate_certs()
        secret = make_secret()
        keys = derive_mask_keys("k1", secret)

        http_srv = ws.enter(LocalHttpServer())
        policy_toml = ws.write_secret("policy.toml", allow_loopback_policy(ports=[http_srv.port]))
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
                limits={
                    "max_pre_auth_connections": 8,
                    "max_pre_auth_per_source": 2,
                    "handshake_timeout_seconds": 0,
                },
                masking={"enabled": False, "quic": True, "quic_key_id": "k1"},
            ),
        )
        chk = run_config_check(ctx.server_bin, srv_toml)
        assert chk.returncode == 0, f"config-check failed: {chk.stderr}\n{chk.stdout}"

        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        # 1. Unmasked TCP client works
        tcp_socks = free_tcp_port()
        tcp_obs = free_tcp_port()
        tcp_cli_toml = ws.write_secret(
            "client_tcp.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{tcp_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{tcp_obs}",
                extra={"max_carrier_sessions": 1},
                masking={"enabled": False},
            ),
        )
        tcp_cli = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                tcp_cli_toml,
                socks_listen=f"127.0.0.1:{tcp_socks}",
                observability_listen=f"127.0.0.1:{tcp_obs}",
            )
        )
        tcp_cli.wait_ready(require_session=True, timeout=15.0)
        st1, _, b1 = Socks5Client.socks5_http_get(
            "127.0.0.1", tcp_socks, "127.0.0.1", http_srv.port, path="/bytes/32768"
        )
        assert st1 == 200 and b1 == deterministic_bytes(32768)

        # 2. Masked QUIC client works
        quic_socks = free_tcp_port()
        quic_obs = free_tcp_port()
        quic_cli_toml = ws.write_secret(
            "client_quic.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{udp_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{quic_obs}",
                extra={"max_carrier_sessions": 1},
                masking={"enabled": False, "quic": True},
            ),
        )
        quic_cli = ws.enter(
            UkClientProcess(
                ctx.client_bin,
                quic_cli_toml,
                socks_listen=f"127.0.0.1:{quic_socks}",
                observability_listen=f"127.0.0.1:{quic_obs}",
            )
        )
        quic_cli.wait_ready(require_session=True, timeout=15.0)
        st2, _, b2 = Socks5Client.socks5_http_get(
            "127.0.0.1", quic_socks, "127.0.0.1", http_srv.port, path="/bytes/32768"
        )
        assert st2 == 200 and b2 == deterministic_bytes(32768)

        # 3. Pre-admission limit=2 enforced on 127.0.0.1
        before_acc = srv.metric("uncrowned_king_server_accepted_connections_total")
        held: List[socket.socket] = []
        try:
            held.append(MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=5.0))
            held.append(MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=5.0))
            srv.wait_for_metric(
                "uncrowned_king_server_accepted_connections_total",
                lambda v: v >= before_acc + 2,
                timeout=5.0,
            )

            s3 = MaskedTcpProbe.open_socket("127.0.0.1", tcp_port, timeout=3.0)
            try:
                r3 = read_until_close(s3, timeout=1.5)
            finally:
                s3.close()
            assert r3.close_kind == CloseKind.RST and r3.elapsed_s < 0.8, (
                f"expected immediate RST on 3rd pre-auth socket, got {r3.close_kind} in {r3.elapsed_s:.3f}s"
            )

            with UdpObserverProxy("127.0.0.1", udp_port) as proxy:
                sat_quic_toml = ws.write_secret(
                    "client_quic_sat.toml",
                    build_client_toml(
                        server_addr=f"quic://127.0.0.1:{proxy.port}",
                        ca_cert_path=certs.ca_cert,
                        key_id="k1",
                        secret=secret,
                        extra={"handshake_timeout_seconds": 1},
                        masking={"enabled": False, "quic": True},
                    ),
                )
                cp_sat = run_client_handshake(ctx.client_bin, sat_quic_toml, timeout=5.0)
                assert cp_sat.returncode != 0, (
                    "expected masked QUIC handshake to fail when per-source pre-auth limit saturated"
                )
                assert len(proxy.c2s) >= 1, (
                    "expected saturated QUIC client to transmit UDP datagrams via proxy"
                )
                non_retry = proxy.non_retry_s2c_packets(keys)
                assert non_retry == [], (
                    f"expected 0 non-Retry QUIC packets when per-source pre-auth limit saturated, "
                    f"got {len(non_retry)}: {[p[:8].hex() for p in non_retry]}"
                )
        finally:
            for s in held:
                try:
                    s.shutdown(socket.SHUT_WR)
                    read_until_close(s, timeout=3.0)
                except OSError:
                    pass
            _close_sockets(held)

        # After releasing held sockets, new unmasked TCP handshake succeeds
        hs = run_client_handshake(ctx.client_bin, tcp_cli_toml, timeout=10.0)
        assert hs.returncode == 0, f"expected TCP handshake recovery: {hs.stderr}\n{hs.stdout}"


# ---------------------------------------------------------------------------
# T3-06: R3 x R6 — Masked QUIC retains masking & MTU across SIGHUP cert rotation
# ---------------------------------------------------------------------------

def t3_06_r3_r6_masked_quic_sighup_cert_rotation(ctx: TestContext) -> None:
    """Masked QUIC retains masking and MTU compatibility across SIGHUP TLS cert rotation; new CA client connects over masked QUIC."""
    with ctx.workspace("t3_06") as ws:
        certs1 = ws.generate_certs(prefix="s1")
        certs2 = ws.generate_certs(prefix="s2")
        secret = make_secret()

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
                cert_path=certs1.cert,
                key_path=certs1.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[{"key_id": "k1", "secret": secret}],
                masking={"enabled": False, "quic": True, "quic_key_id": "k1"},
            ),
        )
        srv = ws.enter(
            UkServerProcess(ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}")
        )
        srv.wait_ready()

        # Client 1 with CA1 succeeds before SIGHUP
        c1_socks = free_tcp_port()
        c1_obs = free_tcp_port()
        c1_toml = ws.write_secret(
            "client1.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{udp_port}",
                ca_cert_path=certs1.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{c1_obs}",
                extra={"max_carrier_sessions": 1, "handshake_timeout_seconds": 3},
                masking={"enabled": False, "quic": True},
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
        st1, _, body1 = Socks5Client.socks5_http_get(
            "127.0.0.1", c1_socks, "127.0.0.1", http_srv.port, path="/bytes/65536"
        )
        assert st1 == 200 and body1 == deterministic_bytes(65536)

        # Rotate TLS cert/key on disk and SIGHUP
        before_gen = srv.metric("uncrowned_king_server_security_generation")
        ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                quic_listen=f"127.0.0.1:{udp_port}",
                cert_path=certs2.cert,
                key_path=certs2.key,
                policy_path=policy_toml,
                observability_listen=f"127.0.0.1:{srv_obs}",
                credentials=[{"key_id": "k1", "secret": secret}],
                masking={"enabled": False, "quic": True, "quic_key_id": "k1"},
            ),
        )
        srv.send_sighup()
        srv.wait_for_metric(
            "uncrowned_king_server_security_generation",
            lambda v: v > before_gen,
            timeout=10.0,
        )
        assert srv.metric("uncrowned_king_server_config_reload_failures_total") == 0

        # Old CA1 must no longer validate new QUIC connections
        old_hs = run_client_handshake(ctx.client_bin, c1_toml, timeout=8.0)
        assert old_hs.returncode != 0, "expected old CA1 client handshake to fail after cert rotation"

        # Unmasked QUIC probe still ignored (masking preserved across SIGHUP)
        with QuicProbeSocket("127.0.0.1", udp_port) as qp:
            qp.send_raw(build_quic_initial_probe(version=QUIC_V1, size=1200))
            assert qp.recv_packets(timeout=0.4) == [], (
                "expected 0 packets for unmasked QUIC after SIGHUP"
            )

        # New Client 2 with CA2 connects over masked QUIC via UdpObserverProxy and relays HTTP + ~1350B UDP datagrams
        # masked_endpoint_config() max_udp_payload_size = 1460 (+12B nonce = 1472B wire);
        # apply_masked_mtu() discovery upper_bound = 1440 (+12B nonce = 1452B wire).
        masked_max_wire_size = 1452
        proxy = ws.enter(UdpObserverProxy("127.0.0.1", udp_port))
        c2_socks = free_tcp_port()
        c2_obs = free_tcp_port()
        c2_toml = ws.write_secret(
            "client2.toml",
            build_client_toml(
                server_addr=f"quic://127.0.0.1:{proxy.port}",
                ca_cert_path=certs2.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{c2_obs}",
                extra={"max_carrier_sessions": 1},
                masking={"enabled": False, "quic": True},
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

        expected_http = deterministic_bytes(262144, seed=0x306)
        http_srv.register("/t3_06", expected_http)
        st2, _, body2 = Socks5Client.socks5_http_get(
            "127.0.0.1", c2_socks, "127.0.0.1", http_srv.port, path="/t3_06"
        )
        assert st2 == 200 and hashlib.sha256(body2).digest() == hashlib.sha256(expected_http).digest()

        udp_payloads = [deterministic_bytes(1350, seed=i + 1) for i in range(4)]
        udp_resps = Socks5Client.socks5_udp_exchange(
            "127.0.0.1", c2_socks, "127.0.0.1", udp_echo.port, udp_payloads
        )
        assert udp_resps == udp_payloads

        c2s_pkts, s2c_pkts = proxy.snapshot()
        all_pkts = c2s_pkts + s2c_pkts
        assert len(all_pkts) > 0, "expected captured masked QUIC wire datagrams post-SIGHUP"
        oversized = [len(p) for p in all_pkts if len(p) > masked_max_wire_size]
        assert not oversized, (
            f"post-SIGHUP masked QUIC wire datagrams exceeded {masked_max_wire_size}B "
            f"(apply_masked_mtu 1440+12): max={max(oversized)}"
        )


# ---------------------------------------------------------------------------
# T3-07: R4 x R5 — Coalesced client graceful drain on SIGTERM
# ---------------------------------------------------------------------------

def t3_07_r4_r5_coalesced_client_graceful_drain_sigterm(ctx: TestContext) -> None:
    """Coalesced masked uk-client streams 256 KiB slow HTTP body while server receives SIGTERM -> clean FIN completion and server exit 0."""
    with ctx.workspace("t3_07") as ws:
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

        proxy = ws.enter(TransparentFirstSegmentProxy("127.0.0.1", srv_port))
        cli_toml = ws.write_secret(
            "client.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{proxy.listen_port}",
                ca_cert_path=certs.ca_cert,
                key_id="k1",
                secret=secret,
                observability_listen=f"127.0.0.1:{cli_obs}",
                extra={"max_carrier_sessions": 1},
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
        first_seg = proxy.wait_for_first_segment(timeout=10.0)
        assert len(first_seg) >= WIRE_PRELUDE_LEN + 5, (
            f"expected coalesced first segment >= 81B, got {len(first_seg)}B"
        )

        total_bytes = 262144
        expected = deterministic_bytes(total_bytes)
        sock = Socks5Client.socks5_connect("127.0.0.1", socks_port, "127.0.0.1", http_srv.port)
        try:
            sock.settimeout(15.0)
            req = (
                f"GET /slow?bytes={total_bytes}&chunk=8192&delay_ms=15 HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{http_srv.port}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            sock.sendall(req)

            buf = bytearray()
            header_end = -1
            while True:
                chunk = sock.recv(16384)
                assert chunk, f"unexpected EOF before initial slow body arrived (got {len(buf)}B)"
                buf += chunk
                if header_end < 0:
                    header_end = buf.find(b"\r\n\r\n")
                if header_end >= 0 and len(buf) - (header_end + 4) >= 16384:
                    break

            # Transfer is demonstrably in-flight; send SIGTERM to uk-server now
            srv.send_sigterm()

            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            sock.close()

        head = bytes(buf[:header_end]).decode("iso-8859-1")
        status_code = int(head.split("\r\n", 1)[0].split(" ", 2)[1])
        body = bytes(buf[header_end + 4 :])
        assert status_code == 200, f"expected HTTP 200, got {status_code}"
        assert len(body) == total_bytes, (
            f"expected full {total_bytes}B after SIGTERM drain, got {len(body)}B"
        )
        assert hashlib.sha256(body).digest() == hashlib.sha256(expected).digest()

        rc = srv.wait_exit(timeout=15.0)
        assert rc == 0, f"expected uk-server clean exit 0 after graceful drain, got {rc}"


# ---------------------------------------------------------------------------
# T3-08: R1 x R6 — Zero handshake timeout fallback with silent bad ClientHello
# ---------------------------------------------------------------------------

def t3_08_r1_r6_zero_timeout_masking_fallback_silent_hello(ctx: TestContext) -> None:
    """handshake_timeout_seconds=0 with masking.enabled=true applies non-zero fallback dwell >=4s on corrupt ClientHello without burning counter."""
    with ctx.workspace("t3_08") as ws:
        certs = ws.generate_certs()
        secret = make_secret()
        keys = derive_mask_keys("k1", secret)
        tcp_port = free_tcp_port()
        obs_port = free_tcp_port()
        obs_addr = f"127.0.0.1:{obs_port}"

        srv_toml = ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{tcp_port}",
                cert_path=certs.cert,
                key_path=certs.key,
                observability_listen=obs_addr,
                credentials=[{"key_id": "k1", "secret": secret}],
                limits={"handshake_timeout_seconds": 0, "auth_rate_limit_failures": 10},
                masking={"enabled": True},
            ),
        )
        chk = run_config_check(ctx.server_bin, srv_toml)
        assert chk.returncode == 0, f"config-check should accept timeout=0: {chk.stderr}\n{chk.stdout}"

        srv = ws.enter(UkServerProcess(ctx.server_bin, srv_toml, observability_listen=obs_addr))
        srv.wait_ready()

        identity = 0x30801
        counter = 3
        res = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            keys=keys,
            identity=identity,
            counter=counter,
            plaintext_after_prelude=b"\x63" * 64,
            timeout=15.0,
            wait_for_close=True,
        )
        assert res.raw_received == b"", (
            f"expected 0 response bytes, got {len(res.raw_received)}B"
        )
        assert res.close_kind == CloseKind.RST, f"expected RST, got {res.close_kind}"
        assert res.elapsed_s >= 4.0, (
            f"expected non-zero fallback dwell >= 4.0s (not instant timeout=0), got {res.elapsed_s:.3f}s"
        )

        # Same (identity, counter) must still succeed with valid ClientHello
        res2 = MaskedTcpProbe.probe_masked(
            "127.0.0.1",
            tcp_port,
            keys=keys,
            identity=identity,
            counter=counter,
            plaintext_after_prelude=build_tls13_client_hello(),
            timeout=5.0,
            wait_for_close=False,
        )
        _assert_server_hello(res2.received, "t3_08 counter reuse after fallback dwell")


# ---------------------------------------------------------------------------
# T3-09: R5 x R6 — SIGHUP credential rotation + coalesced new-key client
# ---------------------------------------------------------------------------

def t3_09_r5_r6_sighup_credential_rotation_coalesced_client(ctx: TestContext) -> None:
    """SIGHUP adds credential k2 -> new uk-client (k2) coalesces >=76+5B via proxy and completes HTTP relay while existing k1 client stays alive."""
    with ctx.workspace("t3_09") as ws:
        certs = ws.generate_certs()
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
                cert_path=certs.cert,
                key_path=certs.key,
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
                ca_cert_path=certs.ca_cert,
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
        st1, _, b1 = Socks5Client.socks5_http_get(
            "127.0.0.1", c1_socks, "127.0.0.1", http_srv.port, path="/bytes/16384"
        )
        assert st1 == 200 and b1 == deterministic_bytes(16384)

        # Rotate credentials on disk (add k2) and SIGHUP
        before_gen = srv.metric("uncrowned_king_server_security_generation")
        ws.write_secret(
            "server.toml",
            build_server_toml(
                listen=f"127.0.0.1:{srv_port}",
                cert_path=certs.cert,
                key_path=certs.key,
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
        srv.wait_for_metric(
            "uncrowned_king_server_security_generation",
            lambda v: v > before_gen,
            timeout=10.0,
        )
        assert srv.metric("uncrowned_king_server_config_reload_failures_total") == 0

        proxy = ws.enter(TransparentFirstSegmentProxy("127.0.0.1", srv_port))
        c2_socks = free_tcp_port()
        c2_obs = free_tcp_port()
        c2_toml = ws.write_secret(
            "client2.toml",
            build_client_toml(
                server_addr=f"tls://127.0.0.1:{proxy.listen_port}",
                ca_cert_path=certs.ca_cert,
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
        first_seg = proxy.wait_for_first_segment(timeout=10.0)
        assert len(first_seg) >= WIRE_PRELUDE_LEN + 5, (
            f"expected k2 coalesced first segment >= 81B, got {len(first_seg)}B"
        )

        # Relay large GET (>64 KiB) and POST via k2 client, plus GET on existing k1 client
        expected = deterministic_bytes(131072)
        st2, _, b2 = Socks5Client.socks5_http_get(
            "127.0.0.1", c2_socks, "127.0.0.1", http_srv.port, path="/bytes/131072"
        )
        assert st2 == 200 and hashlib.sha256(b2).digest() == hashlib.sha256(expected).digest()

        post_body = deterministic_bytes(49152, seed=0x309)
        st_post, _, b_post = Socks5Client.socks5_http_post(
            "127.0.0.1", c2_socks, "127.0.0.1", http_srv.port, path="/sha256", body=post_body
        )
        assert st_post == 200
        assert b_post.decode("ascii").strip() == hashlib.sha256(post_body).hexdigest()

        st1_after, _, b1_after = Socks5Client.socks5_http_get(
            "127.0.0.1", c1_socks, "127.0.0.1", http_srv.port, path="/bytes/32768"
        )
        assert st1_after == 200 and b1_after == deterministic_bytes(32768)


# ---------------------------------------------------------------------------
# T3-10: R3 x R5 — Client failover from blackholed QUIC to coalesced masked TCP
# ---------------------------------------------------------------------------

def t3_10_r3_r5_client_failover_blackholed_quic_to_coalesced_tcp(ctx: TestContext) -> None:
    """uk-client with blackholed quic:// primary and live masked tls:// fallback fails over to coalesced TCP (>=76+5B) and completes curl transfer."""
    with ctx.workspace("t3_10") as ws:
        certs = ws.generate_certs()
        secret = make_secret()

        http_srv = ws.enter(LocalHttpServer())
        policy_toml = ws.write_secret("policy.toml", allow_loopback_policy(ports=[http_srv.port]))
        srv_port = free_tcp_port()
        srv_obs = free_tcp_port()
        cli_obs = free_tcp_port()
        socks_port = free_tcp_port()

        # Bind a silent blackhole UDP socket so QUIC Initial packets drop without ICMP unreachable
        blackhole_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blackhole_udp.bind(("127.0.0.1", 0))
        blackhole_port = int(blackhole_udp.getsockname()[1])

        try:
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
                UkServerProcess(
                    ctx.server_bin, srv_toml, observability_listen=f"127.0.0.1:{srv_obs}"
                )
            )
            srv.wait_ready()

            proxy = ws.enter(TransparentFirstSegmentProxy("127.0.0.1", srv_port))

            cli_toml = ws.write_secret(
                "client.toml",
                build_client_toml(
                    server_addr=f"quic://127.0.0.1:{blackhole_port}",
                    server_addrs=[f"tls://127.0.0.1:{proxy.listen_port}"],
                    ca_cert_path=certs.ca_cert,
                    key_id="k1",
                    secret=secret,
                    observability_listen=f"127.0.0.1:{cli_obs}",
                    extra={
                        "handshake_timeout_seconds": 2,
                        "max_carrier_sessions": 1,
                    },
                    masking={"enabled": True, "quic": True, "prelude_policy": "fade"},
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

            first_seg = proxy.wait_for_first_segment(timeout=10.0)
            assert len(first_seg) >= WIRE_PRELUDE_LEN + 5, (
                f"expected coalesced fallback TCP segment >= 81B, got {len(first_seg)}B"
            )
            assert cli.metric("uncrowned_king_client_endpoint_failures_total", {"phase": "timeout"}) >= 1 or (
                cli.metric("uncrowned_king_client_endpoint_attempts_total", {"outcome": "failure"}) >= 1
            ), "expected client metrics to record primary QUIC endpoint timeout failure"

            expected = deterministic_bytes(131072, seed=0x310)
            http_srv.register("/t3_10", expected)
            url = f"http://127.0.0.1:{http_srv.port}/t3_10"

            curl_bin = shutil.which("curl")
            if curl_bin:
                proc = subprocess.run(
                    [
                        curl_bin,
                        "-fsS",
                        "--max-time",
                        "15",
                        "--socks5-hostname",
                        f"127.0.0.1:{socks_port}",
                        url,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                assert proc.returncode == 0, (
                    f"curl --socks5-hostname failed (rc={proc.returncode}): {proc.stderr.decode('utf-8', 'replace')}"
                )
                assert hashlib.sha256(proc.stdout).digest() == hashlib.sha256(expected).digest()
            else:
                st, _, body = Socks5Client.socks5_http_get(
                    "127.0.0.1", socks_port, "127.0.0.1", http_srv.port, path="/t3_10"
                )
                assert st == 200
                assert hashlib.sha256(body).digest() == hashlib.sha256(expected).digest()
        finally:
            blackhole_udp.close()


def collect_tests(_ctx: TestContext) -> List[E2ETestCase]:
    return [
        E2ETestCase(
            name="t3_01_r1_r4_delayed_corrupt_hello_shared_deadline",
            tier=3,
            requirement="R1+R4",
            fn=t3_01_r1_r4_delayed_corrupt_hello_shared_deadline,
            description="Valid prelude + corrupt ClientHello delayed 1.2s into 2s deadline closes via RST within budget without burning counter.",
        ),
        E2ETestCase(
            name="t3_02_r1_r2_source_saturation_with_concurrent_bad_hello",
            tier=3,
            requirement="R1+R2",
            fn=t3_02_r1_r2_source_saturation_with_concurrent_bad_hello,
            description="Source ::1 saturates max_pre_auth_per_source while 127.0.0.1 triggers R1 silent corrupt-hello without burning counter.",
        ),
        E2ETestCase(
            name="t3_03_r1_r5_coalesced_client_vs_racing_replay",
            tier=3,
            requirement="R1+R5",
            fn=t3_03_r1_r5_coalesced_client_vs_racing_replay,
            description="Coalesced uk-client (>=76+5B) succeeds while replayed prelude+ClientHello is silently rejected with RST.",
        ),
        E2ETestCase(
            name="t3_04_r2_r3_shared_pre_admission_tcp_and_quic",
            tier=3,
            requirement="R2+R3",
            fn=t3_04_r2_r3_shared_pre_admission_tcp_and_quic,
            description="Saturated TCP pre-admission causes masked QUIC incoming.ignore(); releasing 1 slot allows QUIC uk-client.",
        ),
        E2ETestCase(
            name="t3_05_r2_r6_split_mode_with_pre_admission_and_zero_timeout",
            tier=3,
            requirement="R2+R6",
            fn=t3_05_r2_r6_split_mode_with_pre_admission_and_zero_timeout,
            description="Split mode (TCP unmasked, QUIC masked) + timeout=0 + pre-admission limit works and enforces limits.",
        ),
        E2ETestCase(
            name="t3_06_r3_r6_masked_quic_sighup_cert_rotation",
            tier=3,
            requirement="R3+R6",
            fn=t3_06_r3_r6_masked_quic_sighup_cert_rotation,
            description="Masked QUIC retains masking and MTU across SIGHUP cert rotation.",
        ),
        E2ETestCase(
            name="t3_07_r4_r5_coalesced_client_graceful_drain_sigterm",
            tier=3,
            requirement="R4+R5",
            fn=t3_07_r4_r5_coalesced_client_graceful_drain_sigterm,
            description="Coalesced masked uk-client active 256 KiB slow stream completes cleanly on server SIGTERM.",
        ),
        E2ETestCase(
            name="t3_08_r1_r6_zero_timeout_masking_fallback_silent_hello",
            tier=3,
            requirement="R1+R6",
            fn=t3_08_r1_r6_zero_timeout_masking_fallback_silent_hello,
            description="handshake_timeout_seconds=0 with masking.enabled=true dwells >=4s on corrupt ClientHello without burning counter.",
        ),
        E2ETestCase(
            name="t3_09_r5_r6_sighup_credential_rotation_coalesced_client",
            tier=3,
            requirement="R5+R6",
            fn=t3_09_r5_r6_sighup_credential_rotation_coalesced_client,
            description="SIGHUP adds credential k2 and coalesced k2 uk-client completes HTTP relay.",
        ),
        E2ETestCase(
            name="t3_10_r3_r5_client_failover_blackholed_quic_to_coalesced_tcp",
            tier=3,
            requirement="R3+R5",
            fn=t3_10_r3_r5_client_failover_blackholed_quic_to_coalesced_tcp,
            description="Client fails over from blackholed quic:// to coalesced masked tls:// and completes curl transfer.",
        ),
    ]
