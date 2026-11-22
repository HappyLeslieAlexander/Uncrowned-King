"""Opaque-box E2E harness for Uncrowned King: ephemeral workspaces, OpenSSL SAN
cert generation, 0600 TOML/policy writers, uk-server/uk-client process managers,
Prometheus /metrics + /readyz + JSON-log pollers, loopback multi-source
discovery, and deterministic local HTTP/TCP/UDP targets.
"""

from contextlib import ExitStack
from dataclasses import dataclass, field
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse


# ---------------------------------------------------------------------------
# Ports & Loopback Source Discovery
# ---------------------------------------------------------------------------

def format_host_port(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def split_host_port(addr: str) -> Tuple[str, int]:
    if addr.startswith("["):
        end = addr.index("]")
        host = addr[1:end]
        rest = addr[end + 1 :]
        if not rest.startswith(":"):
            raise ValueError(f"missing port in {addr!r}")
        return host, int(rest[1:])
    host, port_str = addr.rsplit(":", 1)
    return host, int(port_str)


def free_tcp_port(host: str = "127.0.0.1") -> int:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def free_udp_port(host: str = "127.0.0.1") -> int:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def free_dual_port(host: str = "127.0.0.1") -> int:
    """Allocate a port free on both TCP and UDP for `host`."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for _ in range(32):
        with socket.socket(family, socket.SOCK_STREAM) as tcp_s:
            tcp_s.bind((host, 0))
            port = int(tcp_s.getsockname()[1])
            with socket.socket(family, socket.SOCK_DGRAM) as udp_s:
                try:
                    udp_s.bind((host, port))
                    return port
                except OSError:
                    continue
    raise RuntimeError(f"failed to find dual free TCP+UDP port on {host}")


def discover_loopback_sources(
    candidates: Sequence[str] = ("127.0.0.1", "::1", "fe80::1%lo0", "127.0.0.2"),
) -> List[str]:
    """Probe candidate local source addresses at runtime without root privileges."""
    usable: List[str] = []
    for addr in candidates:
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        try:
            infos = socket.getaddrinfo(addr, 0, family, socket.SOCK_STREAM)
            if not infos:
                continue
            sockaddr = infos[0][4]
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.bind(sockaddr)
            usable.append(addr)
        except OSError:
            continue
    return usable


# ---------------------------------------------------------------------------
# Secrets, Certificates & 0600 TOML/Policy Writers
# ---------------------------------------------------------------------------

def write_secret_file(path: Path, content: str, mode: int = 0o600) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.tmp.",
            delete=False,
        ) as fh:
            tmp_path = Path(fh.name)
            fh.write(content)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        os.chmod(path, mode)
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
    return path


def make_secret(num_bytes: int = 32) -> str:
    """Generate a base64 random secret (>= 32 UTF-8 bytes)."""
    if num_bytes < 24:
        raise ValueError("num_bytes must be >= 24 so base64 output >= 32 bytes")
    return base64.b64encode(os.urandom(num_bytes)).decode("ascii")


@dataclass(frozen=True)
class CertBundle:
    ca_cert: Path
    ca_key: Path
    cert: Path
    key: Path


def _run_openssl(args: Sequence[str]) -> None:
    proc = subprocess.run(
        ["openssl", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"openssl {' '.join(args)} failed (rc={proc.returncode}): {proc.stderr}"
        )


def generate_test_certs(
    workdir: Path,
    san_dns: Sequence[str] = ("localhost",),
    san_ips: Sequence[str] = ("127.0.0.1", "::1"),
    cn: str = "localhost",
    prefix: str = "server",
    ca_cert: Optional[Path] = None,
    ca_key: Optional[Path] = None,
) -> CertBundle:
    """Generate an ephemeral CA (if not provided) and SAN leaf cert/key pair."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    if ca_cert is None or ca_key is None:
        ca_cert = workdir / f"{prefix}-ca-cert.pem"
        ca_key = workdir / f"{prefix}-ca-key.pem"
        _run_openssl(
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_cert),
                "-days",
                "1",
                "-subj",
                f"/CN=UK-Test-CA-{prefix}",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ]
        )
        os.chmod(ca_key, 0o600)
        os.chmod(ca_cert, 0o644)

    cert = workdir / f"{prefix}-cert.pem"
    key = workdir / f"{prefix}-key.pem"
    csr = workdir / f"{prefix}.csr"
    extfile = workdir / f"{prefix}.ext"

    san_parts = [f"DNS:{d}" for d in san_dns] + [f"IP:{ip}" for ip in san_ips]
    ext_content = f"subjectAltName={','.join(san_parts)}\nbasicConstraints=CA:FALSE\n"
    extfile.write_text(ext_content, encoding="utf-8")

    _run_openssl(
        [
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={cn}",
        ]
    )
    _run_openssl(
        [
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            "1",
            "-extfile",
            str(extfile),
        ]
    )
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    return CertBundle(ca_cert=ca_cert, ca_key=ca_key, cert=cert, key=key)


def _toml_val(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, str):
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(val, Path):
        return _toml_val(str(val))
    if isinstance(val, (list, tuple)):
        return "[" + ", ".join(_toml_val(v) for v in val) + "]"
    raise TypeError(f"unsupported TOML value type: {type(val).__name__}")


def build_policy_toml(rules: Sequence[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for rule in rules:
        lines.append("[[rules]]")
        for k, v in rule.items():
            if v is not None:
                lines.append(f"{k} = {_toml_val(v)}")
        lines.append("")
    return "\n".join(lines)


def allow_loopback_policy(
    ports: Optional[Sequence[int]] = None,
    allow_v6: bool = True,
    extra_rules: Sequence[Dict[str, Any]] = (),
) -> str:
    rules: List[Dict[str, Any]] = []
    cidrs = ["127.0.0.1/32"] + (["::1/128"] if allow_v6 else [])
    if ports:
        for p in ports:
            for cidr in cidrs:
                rules.append(
                    {
                        "action": "allow",
                        "cidr": cidr,
                        "port_start": p,
                        "port_end": p,
                        "private": True,
                    }
                )
    else:
        for cidr in cidrs:
            rules.append({"action": "allow", "cidr": cidr, "private": True})
    rules.extend(extra_rules)
    return build_policy_toml(rules)


def build_server_toml(
    *,
    listen: str,
    cert_path: Path,
    key_path: Path,
    credentials: Sequence[Dict[str, Any]],
    policy_path: Optional[Path] = None,
    quic_listen: Optional[str] = None,
    observability_listen: Optional[str] = None,
    auth_skew_seconds: Optional[int] = None,
    limits: Optional[Dict[str, Any]] = None,
    masking: Optional[Dict[str, Any]] = None,
) -> str:
    lines: List[str] = [
        f"listen = {_toml_val(listen)}",
        f"cert_path = {_toml_val(cert_path)}",
        f"key_path = {_toml_val(key_path)}",
    ]
    if quic_listen is not None:
        lines.append(f"quic_listen = {_toml_val(quic_listen)}")
    if observability_listen is not None:
        lines.append(f"observability_listen = {_toml_val(observability_listen)}")
    if policy_path is not None:
        lines.append(f"policy_path = {_toml_val(policy_path)}")
    if auth_skew_seconds is not None:
        lines.append(f"auth_skew_seconds = {_toml_val(auth_skew_seconds)}")
    lines.append("")

    if limits is not None:
        lines.append("[limits]")
        for k, v in limits.items():
            if v is not None:
                lines.append(f"{k} = {_toml_val(v)}")
        lines.append("")

    for cred in credentials:
        lines.append("[[credentials]]")
        for k, v in cred.items():
            if v is not None:
                lines.append(f"{k} = {_toml_val(v)}")
        lines.append("")

    if masking is not None:
        lines.append("[masking]")
        for k, v in masking.items():
            if v is not None:
                lines.append(f"{k} = {_toml_val(v)}")
        lines.append("")

    return "\n".join(lines)


def build_client_toml(
    *,
    server_addr: str,
    ca_cert_path: Path,
    key_id: str,
    secret: str,
    server_name: str = "localhost",
    server_addrs: Optional[Sequence[str]] = None,
    observability_listen: Optional[str] = None,
    masking: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    lines: List[str] = [
        f"server_addr = {_toml_val(server_addr)}",
        f"server_name = {_toml_val(server_name)}",
        f"ca_cert_path = {_toml_val(ca_cert_path)}",
        f"key_id = {_toml_val(key_id)}",
        f"secret = {_toml_val(secret)}",
    ]
    if server_addrs is not None:
        lines.append(f"server_addrs = {_toml_val(list(server_addrs))}")
    if observability_listen is not None:
        lines.append(f"observability_listen = {_toml_val(observability_listen)}")
    if extra:
        for k, v in extra.items():
            if v is not None:
                lines.append(f"{k} = {_toml_val(v)}")
    lines.append("")

    if masking is not None:
        lines.append("[masking]")
        for k, v in masking.items():
            if v is not None:
                lines.append(f"{k} = {_toml_val(v)}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTTP Observability & Prometheus Parser
# ---------------------------------------------------------------------------

def http_get_bytes(
    addr_or_host: str,
    port: Optional[int] = None,
    path: str = "/metrics",
    timeout: float = 3.0,
) -> Tuple[int, bytes]:
    if port is None:
        host, port = split_host_port(addr_or_host)
    else:
        host = addr_or_host
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


def http_get(
    addr_or_host: str,
    port: Optional[int] = None,
    path: str = "/metrics",
    timeout: float = 3.0,
) -> Tuple[int, str]:
    status, raw = http_get_bytes(addr_or_host, port=port, path=path, timeout=timeout)
    return status, raw.decode("utf-8", errors="replace")


_METRIC_LINE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|NaN|[+-]?Inf)$"
)
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_prometheus_metrics(
    text: str,
) -> Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float]:
    """Parse Prometheus text format into {(name, sorted_label_pairs): float_val}."""
    out: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _METRIC_LINE_RE.match(line)
        if not m:
            continue
        name, labels_str, val_str = m.group(1), m.group(2), m.group(3)
        if labels_str:
            pairs = tuple(
                sorted(
                    (k, v.replace('\\"', '"').replace("\\\\", "\\"))
                    for k, v in _LABEL_RE.findall(labels_str)
                )
            )
        else:
            pairs = ()
        out[(name, pairs)] = float(val_str)
    return out


def get_metric(
    metrics: Any,
    name: str,
    labels: Optional[Dict[str, str]] = None,
    default: float = 0.0,
) -> float:
    parsed = parse_prometheus_metrics(metrics) if isinstance(metrics, str) else metrics
    key_labels = tuple(sorted((labels or {}).items()))
    return parsed.get((name, key_labels), default)


def wait_for_metric(
    obs_addr: str,
    name: str,
    predicate: Callable[[float], bool],
    labels: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    poll_interval: float = 0.02,
    default: float = 0.0,
) -> float:
    deadline = time.monotonic() + timeout
    last_val = default
    last_text = ""
    while True:
        try:
            status, body = http_get(obs_addr, path="/metrics", timeout=2.0)
            if status == 200:
                last_text = body
                last_val = get_metric(body, name, labels=labels, default=default)
                if predicate(last_val):
                    return last_val
        except OSError:
            pass
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError(
                f"timed out waiting for metric {name}{labels or {}} "
                f"(last={last_val}); metrics tail:\n{last_text[-800:]}"
            )
        time.sleep(min(poll_interval, rem))


# ---------------------------------------------------------------------------
# Subprocess Managers: uk-server & uk-client
# ---------------------------------------------------------------------------

def run_config_check(
    bin_path: Path, config_path: Path, timeout: float = 10.0
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(bin_path), "--config", str(config_path), "config-check"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_client_handshake(
    client_bin: Path,
    config_path: Path,
    log_format: str = "json",
    timeout: float = 15.0,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            str(client_bin),
            "--config",
            str(config_path),
            "--log-format",
            log_format,
            "handshake",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


class _ManagedUkProcess:
    def __init__(
        self,
        cmd: Sequence[str],
        observability_listen: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        name: str = "uk-proc",
    ) -> None:
        self.cmd = list(cmd)
        self.observability_listen = observability_listen
        self.name = name
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        self.proc = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=merged_env,
        )
        self._cond = threading.Condition()
        self.logs: List[str] = []
        self.json_events: List[Dict[str, Any]] = []
        self._eof = False
        self._reader = threading.Thread(
            target=self._read_loop, name=f"{name}-log-reader", daemon=True
        )
        self._reader.start()

    def _read_loop(self) -> None:
        assert self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                stripped = line.rstrip("\r\n")
                parsed: Optional[Dict[str, Any]] = None
                if stripped.startswith("{"):
                    try:
                        obj = json.loads(stripped)
                        if isinstance(obj, dict):
                            parsed = obj
                    except json.JSONDecodeError:
                        pass
                with self._cond:
                    self.logs.append(stripped)
                    if parsed is not None:
                        self.json_events.append(parsed)
                    self._cond.notify_all()
        finally:
            with self._cond:
                self._eof = True
                self._cond.notify_all()

    def logs_text(self) -> str:
        with self._cond:
            return "\n".join(self.logs)

    def has_log_event(self, event_name: str) -> bool:
        with self._cond:
            for ev in self.json_events:
                fields = ev.get("fields")
                if isinstance(fields, dict) and fields.get("event") == event_name:
                    return True
                if ev.get("event") == event_name:
                    return True
            return False

    def find_log_messages(self, substr: str) -> List[str]:
        with self._cond:
            return [line for line in self.logs if substr in line]

    def wait_for_log_event(
        self, event_name: str, timeout: float = 10.0, min_count: int = 1
    ) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                matches: List[Dict[str, Any]] = []
                for ev in self.json_events:
                    fields = ev.get("fields")
                    ev_val = (
                        fields.get("event")
                        if isinstance(fields, dict)
                        else ev.get("event")
                    )
                    if ev_val == event_name:
                        matches.append(ev)
                if len(matches) >= min_count:
                    return matches[-1]
                if self.proc.poll() is not None and self._eof:
                    raise RuntimeError(
                        f"{self.name} exited (rc={self.proc.returncode}) before event "
                        f"{event_name!r}; logs:\n" + "\n".join(self.logs[-40:])
                    )
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(
                        f"{self.name} timed out waiting for event {event_name!r}; logs:\n"
                        + "\n".join(self.logs[-40:])
                    )
                self._cond.wait(timeout=min(0.1, rem))

    def get_metrics(self) -> str:
        if not self.observability_listen:
            raise RuntimeError(f"{self.name} has no observability_listen configured")
        status, body = http_get(self.observability_listen, path="/metrics", timeout=3.0)
        if status != 200:
            raise RuntimeError(f"GET /metrics returned HTTP {status}: {body}")
        return body

    def metric(
        self, name: str, labels: Optional[Dict[str, str]] = None, default: float = 0.0
    ) -> float:
        return get_metric(self.get_metrics(), name, labels=labels, default=default)

    def wait_for_metric(
        self,
        name: str,
        predicate: Callable[[float], bool],
        labels: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        poll_interval: float = 0.02,
        default: float = 0.0,
    ) -> float:
        if not self.observability_listen:
            raise RuntimeError(f"{self.name} has no observability_listen configured")
        return wait_for_metric(
            self.observability_listen,
            name,
            predicate,
            labels=labels,
            timeout=timeout,
            poll_interval=poll_interval,
            default=default,
        )

    def send_sighup(self) -> None:
        self.proc.send_signal(signal.SIGHUP)

    def send_sigterm(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()

    def wait_exit(self, timeout: float = 15.0) -> int:
        rc = self.proc.wait(timeout=timeout)
        self._reader.join(timeout=2.0)
        return rc

    def stop(self, timeout: float = 10.0) -> int:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5.0)
        rc = self.proc.returncode if self.proc.returncode is not None else -1
        self._reader.join(timeout=2.0)
        if self.proc.stdout is not None:
            try:
                self.proc.stdout.close()
            except OSError:
                pass
        return rc

    def __enter__(self) -> "_ManagedUkProcess":
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()


class UkServerProcess(_ManagedUkProcess):
    """Managed `uk-server` subprocess."""

    def __init__(
        self,
        server_bin: Path,
        config_path: Path,
        observability_listen: Optional[str] = None,
        log_format: str = "json",
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        cmd = [
            str(server_bin),
            "--config",
            str(config_path),
            "--log-format",
            log_format,
            "serve",
        ]
        super().__init__(
            cmd,
            observability_listen=observability_listen,
            env=env,
            name="uk-server",
        )

    def wait_ready(self, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        if self.observability_listen:
            while True:
                if self.proc.poll() is not None:
                    self._reader.join(timeout=1.0)
                    raise RuntimeError(
                        f"uk-server exited early (rc={self.proc.returncode}):\n"
                        + self.logs_text()
                    )
                try:
                    status, _ = http_get(
                        self.observability_listen, path="/readyz", timeout=1.0
                    )
                    if status == 200:
                        return
                except OSError:
                    pass
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(
                        "uk-server /readyz did not become 200:\n" + self.logs_text()
                    )
                time.sleep(min(0.02, rem))
        else:
            self.wait_for_log_event("server.listen", timeout=timeout)


class UkClientProcess(_ManagedUkProcess):
    """Managed `uk-client socks5` subprocess."""

    def __init__(
        self,
        client_bin: Path,
        config_path: Path,
        socks_listen: str,
        observability_listen: Optional[str] = None,
        log_format: str = "json",
        allow_non_loopback: bool = False,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        self.socks_listen = socks_listen
        cmd = [
            str(client_bin),
            "--config",
            str(config_path),
            "--log-format",
            log_format,
            "socks5",
            "--listen",
            socks_listen,
        ]
        if allow_non_loopback:
            cmd.append("--allow-non-loopback")
        super().__init__(
            cmd,
            observability_listen=observability_listen,
            env=env,
            name="uk-client",
        )

    def wait_ready(
        self, require_session: bool = False, timeout: float = 15.0
    ) -> None:
        self.wait_for_log_event("socks5.listen", timeout=timeout)
        if not self.observability_listen:
            return
        deadline = time.monotonic() + timeout
        path = "/readyz" if require_session else "/healthz"
        while True:
            if self.proc.poll() is not None:
                self._reader.join(timeout=1.0)
                raise RuntimeError(
                    f"uk-client exited early (rc={self.proc.returncode}):\n"
                    + self.logs_text()
                )
            try:
                status, _ = http_get(self.observability_listen, path=path, timeout=1.0)
                if status == 200:
                    return
            except OSError:
                pass
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(
                    f"uk-client {path} did not become 200:\n" + self.logs_text()
                )
            time.sleep(min(0.02, rem))


# ---------------------------------------------------------------------------
# Deterministic Local Target Servers (HTTP, TCP Echo, UDP Echo)
# ---------------------------------------------------------------------------

def deterministic_bytes(size: int, seed: int = 0x554B) -> bytes:
    """Fast deterministic pseudo-random byte payload of exact `size`."""
    if size <= 0:
        return b""
    out = bytearray()
    counter = 0
    seed_b = seed.to_bytes(4, "big")
    while len(out) < size:
        out += hashlib.sha256(seed_b + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:size])


class LocalHttpServer:
    """Deterministic local HTTP/1.1 target supporting GET/POST/slow-stream."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.routes: Dict[str, bytes] = {}
        self.stop_event = threading.Event()
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    body = b"ok\n"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if parsed.path in parent.routes:
                    body = parent.routes[parsed.path]
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if parsed.path.startswith("/bytes/"):
                    size = int(parsed.path.split("/", 2)[2])
                    body = deterministic_bytes(size)
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if parsed.path == "/slow":
                    qs = parse_qs(parsed.query)
                    total = int(qs.get("bytes", ["65536"])[0])
                    chunk_sz = int(qs.get("chunk", ["4096"])[0])
                    delay_ms = float(qs.get("delay_ms", ["20"])[0])
                    payload = deterministic_bytes(total)
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    off = 0
                    while off < len(payload) and not parent.stop_event.is_set():
                        part = payload[off : off + chunk_sz]
                        self.wfile.write(part)
                        self.wfile.flush()
                        off += len(part)
                        if off < len(payload) and delay_ms > 0:
                            parent.stop_event.wait(delay_ms / 1000.0)
                    return

                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length > 0 else b""
                parsed = urlparse(self.path)
                if parsed.path == "/sha256":
                    resp = hashlib.sha256(body).hexdigest().encode("ascii")
                else:
                    resp = body
                self.send_response(200)
                self.send_header("Content-Length", str(len(resp)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(resp)

        class _Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
            daemon_threads = True
            request_queue_size = 128

        self._server = _Server((host, port), Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="uk-local-http", daemon=True
        )

    def register(self, path: str, data: bytes) -> None:
        self.routes[path] = data

    def start(self) -> "LocalHttpServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.stop_event.set()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=3.0)

    def __enter__(self) -> "LocalHttpServer":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.stop()


class LocalTcpEchoServer:
    """Deterministic TCP echo server with optional slow-reading mode."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        read_chunk_size: int = 65536,
        read_delay_s: float = 0.0,
        echo: bool = True,
    ) -> None:
        self.host = host
        self.read_chunk_size = read_chunk_size
        self.read_delay_s = read_delay_s
        self.echo = echo

        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._sock = socket.socket(family, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(64)
        self._sock.setblocking(False)
        self.port = int(self._sock.getsockname()[1])

        self._stop_event = threading.Event()
        self._cond = threading.Condition()
        self.total_received = 0
        self.per_conn_received: List[bytes] = []
        self._threads: List[threading.Thread] = []
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="uk-tcp-echo", daemon=True
        )

    def start(self) -> "LocalTcpEchoServer":
        self._accept_thread.start()
        return self

    def stop(self) -> None:
        self._stop_event.set()
        self._accept_thread.join(timeout=3.0)
        try:
            self._sock.close()
        except OSError:
            pass
        for t in list(self._threads):
            t.join(timeout=3.0)

    def __enter__(self) -> "LocalTcpEchoServer":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.stop()

    def wait_for_total_received(self, min_bytes: int, timeout: float = 10.0) -> int:
        deadline = time.monotonic() + timeout
        with self._cond:
            while self.total_received < min_bytes:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(
                        f"LocalTcpEchoServer received {self.total_received} < {min_bytes} bytes"
                    )
                self._cond.wait(timeout=min(0.1, rem))
            return self.total_received

    def _accept_loop(self) -> None:
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._sock, selectors.EVENT_READ)
            while not self._stop_event.is_set():
                try:
                    events = sel.select(timeout=0.05)
                except (OSError, ValueError):
                    break
                if not events:
                    continue
                try:
                    conn, _addr = self._sock.accept()
                except OSError:
                    break
                t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
                self._threads.append(t)
                t.start()
        finally:
            sel.close()

    def _handle_conn(self, conn: socket.socket) -> None:
        buf = bytearray()
        try:
            conn.settimeout(0.2)
            while not self._stop_event.is_set():
                try:
                    data = conn.recv(self.read_chunk_size)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                buf += data
                with self._cond:
                    self.total_received += len(data)
                    self._cond.notify_all()
                if self.echo:
                    try:
                        conn.sendall(data)
                    except OSError:
                        break
                if self.read_delay_s > 0:
                    self._stop_event.wait(self.read_delay_s)
        finally:
            with self._cond:
                self.per_conn_received.append(bytes(buf))
                self._cond.notify_all()
            try:
                conn.close()
            except OSError:
                pass


class LocalUdpEchoServer:
    """Deterministic selectors-based UDP echo server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._sock = socket.socket(family, socket.SOCK_DGRAM)
        self._sock.bind((host, port))
        self._sock.setblocking(False)
        self.port = int(self._sock.getsockname()[1])
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self.received_packets: List[bytes] = []
        self._thread = threading.Thread(
            target=self._run, name="uk-udp-echo", daemon=True
        )

    def start(self) -> "LocalUdpEchoServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop_event.set()
        self._thread.join(timeout=3.0)
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> "LocalUdpEchoServer":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.stop()

    def _run(self) -> None:
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._sock, selectors.EVENT_READ)
            while not self._stop_event.is_set():
                try:
                    events = sel.select(timeout=0.05)
                except (OSError, ValueError):
                    break
                if not events:
                    continue
                while True:
                    try:
                        pkt, addr = self._sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    except OSError:
                        return
                    with self._lock:
                        self.received_packets.append(pkt)
                    try:
                        self._sock.sendto(pkt, addr)
                    except OSError:
                        pass
        finally:
            sel.close()


# ---------------------------------------------------------------------------
# Workspace & Test Context
# ---------------------------------------------------------------------------

class EphemeralWorkspace:
    """Per-test temp workspace managing ExitStack resources and cleanup."""

    def __init__(self, prefix: str = "uk_e2e_", keep_artifacts: bool = False) -> None:
        self.path = Path(tempfile.mkdtemp(prefix=prefix))
        self.keep_artifacts = keep_artifacts
        self.stack = ExitStack()

    def __enter__(self) -> "EphemeralWorkspace":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        try:
            self.stack.close()
        finally:
            if not self.keep_artifacts:
                shutil.rmtree(self.path, ignore_errors=True)

    def write_secret(self, rel_path: str, content: str, mode: int = 0o600) -> Path:
        return write_secret_file(self.path / rel_path, content, mode=mode)

    def generate_certs(self, **kwargs: Any) -> CertBundle:
        return generate_test_certs(self.path, **kwargs)

    def enter(self, resource: Any) -> Any:
        return self.stack.enter_context(resource)


@dataclass
class TestContext:
    bin_dir: Path
    repo_root: Path
    keep_artifacts: bool = False
    verbose: bool = False

    @property
    def server_bin(self) -> Path:
        return self.bin_dir / "uk-server"

    @property
    def client_bin(self) -> Path:
        return self.bin_dir / "uk-client"

    def workspace(self, name: str = "case") -> EphemeralWorkspace:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name)[:48]
        return EphemeralWorkspace(
            prefix=f"uk_e2e_{safe}_", keep_artifacts=self.keep_artifacts
        )


@dataclass
class E2ETestCase:
    name: str
    tier: int
    fn: Callable[[TestContext], None]
    requirement: str = ""
    description: str = ""
