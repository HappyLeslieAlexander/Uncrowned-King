#!/usr/bin/env bash
#
# Real-client interop check:
#
#     curl --socks5-hostname -> uk-client -> uk-server -> HTTP target
#
# over both the TLS/TCP and QUIC carriers, using the actual built binaries and a
# real curl + HTTP server. Verifies that UK's SOCKS5 front end and relay work
# end to end with a real client, not just the in-crate test harness.
#
# Requirements: cargo, curl, python3, openssl. Run from anywhere:
#
#     ./scripts/interop-curl.sh
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

workdir="$(mktemp -d)"
declare -a bg_pids=()
cleanup() {
    for pid in "${bg_pids[@]:-}"; do
        if [[ -n "${pid}" ]]; then
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
    done
    rm -rf "${workdir}"
}
trap cleanup EXIT

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_for_tcp() {
    local host="$1" port="$2" tries=100
    for _ in $(seq "${tries}"); do
        if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2)
try:
    s.connect(('${host}', ${port})); s.close()
except OSError:
    sys.exit(1)" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "timed out waiting for ${host}:${port}" >&2
    return 1
}

echo "==> Building uk-server and uk-client"
cargo build -q -p uk-server -p uk-client

server_bin="target/debug/uk-server"
client_bin="target/debug/uk-client"

# --- Test content + HTTP target -------------------------------------------------
target_port="$(free_port)"
mkdir -p "${workdir}/www"
head -c 131072 /dev/urandom | base64 > "${workdir}/www/payload.txt"
expected_sha="$(shasum -a 256 "${workdir}/www/payload.txt" | awk '{print $1}')"

echo "==> Starting HTTP target on 127.0.0.1:${target_port}"
( cd "${workdir}/www" && exec python3 -m http.server "${target_port}" --bind 127.0.0.1 ) \
    >/dev/null 2>&1 &
bg_pids+=("$!")
wait_for_tcp 127.0.0.1 "${target_port}"

# --- TLS/QUIC identity + policy + credentials ----------------------------------
cert="${workdir}/server-cert.pem"
key="${workdir}/server-key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${key}" -out "${cert}" \
    -days 1 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
chmod 600 "${key}"

secret="$(head -c 32 /dev/urandom | base64)"

cat > "${workdir}/policy.toml" <<EOF
[[rules]]
action = "allow"
cidr = "127.0.0.1/32"
port_start = ${target_port}
port_end = ${target_port}
EOF

server_tcp="$(free_port)"
server_quic="$(free_port)"

cat > "${workdir}/server.toml" <<EOF
listen = "127.0.0.1:${server_tcp}"
quic_listen = "127.0.0.1:${server_quic}"
cert_path = "${cert}"
key_path = "${key}"
policy_path = "${workdir}/policy.toml"

[[credentials]]
key_id = "interop"
secret = "${secret}"
status = "active"
policy_group = "default"
EOF
chmod 600 "${workdir}/server.toml"

echo "==> Starting uk-server (TLS 127.0.0.1:${server_tcp}, QUIC 127.0.0.1:${server_quic})"
"${server_bin}" --config "${workdir}/server.toml" serve >/dev/null 2>&1 &
bg_pids+=("$!")
wait_for_tcp 127.0.0.1 "${server_tcp}"

# --- Per-carrier client + curl -------------------------------------------------
run_carrier() {
    local name="$1" server_addr="$2"
    local socks_port
    socks_port="$(free_port)"
    local client_conf="${workdir}/client-${name}.toml"
    cat > "${client_conf}" <<EOF
server_addr = "${server_addr}"
server_name = "localhost"
ca_cert_path = "${cert}"
key_id = "interop"
secret = "${secret}"
EOF
    chmod 600 "${client_conf}"

    "${client_bin}" --config "${client_conf}" socks5 --listen "127.0.0.1:${socks_port}" \
        >/dev/null 2>&1 &
    local client_pid="$!"
    bg_pids+=("${client_pid}")
    wait_for_tcp 127.0.0.1 "${socks_port}"

    local got_sha
    got_sha="$(curl -fsS --max-time 15 \
        --socks5-hostname "127.0.0.1:${socks_port}" \
        "http://127.0.0.1:${target_port}/payload.txt" \
        | shasum -a 256 | awk '{print $1}')"

    kill "${client_pid}" 2>/dev/null || true

    if [[ "${got_sha}" == "${expected_sha}" ]]; then
        echo "PASS: ${name} carrier relayed 128 KiB HTTP body intact"
    else
        echo "FAIL: ${name} carrier body mismatch (${got_sha} != ${expected_sha})" >&2
        return 1
    fi
}

echo "==> curl over TLS/TCP carrier"
run_carrier tls "127.0.0.1:${server_tcp}"

echo "==> curl over QUIC carrier"
run_carrier quic "quic://127.0.0.1:${server_quic}"

echo "==> Interop OK: both carriers relayed a real curl HTTP request end to end"
