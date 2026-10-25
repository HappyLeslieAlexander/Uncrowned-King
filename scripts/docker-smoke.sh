#!/usr/bin/env bash
# End-to-end Docker smoke test: builds nothing itself, but runs the already
# built images (`docker build --target server|client -t uncrowned-king-<t>:ci`)
# through a full relay path:
#
#   host curl -> client SOCKS5 -> UK carrier (TLS) -> server -> busybox httpd
#
# Also verifies the documented runtime constraints: config/keys must be 0600
# and owned by the container UID, and `config-check` passes in-container.
set -euo pipefail

cd "$(dirname "$0")/.."

SERVER_IMAGE="${SERVER_IMAGE:-uncrowned-king-server:ci}"
CLIENT_IMAGE="${CLIENT_IMAGE:-uncrowned-king-client:ci}"
BUSYBOX=busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
WORK="$(mktemp -d)"
NET=uk-smoke-$$
trap 'docker rm -f uk-target uk-server uk-client >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

docker network create "$NET" >/dev/null

# --- target -------------------------------------------------------------------
mkdir "$WORK/www"
echo "uk-docker-smoke-ok" > "$WORK/www/index.html"
docker run -d --name uk-target --network "$NET" \
    -v "$WORK/www:/www:ro" "$BUSYBOX" httpd -f -p 8080 -h /www >/dev/null

# --- TLS material + configs ---------------------------------------------------
# A minimal two-certificate chain: a self-signed CA (basicConstraints CA:TRUE)
# and a server leaf signed by it. rustls/webpki rejects a CA certificate used
# directly as an end-entity certificate (CaUsedAsEndEntity), so the smoke
# cannot present one self-signed certificate as both trust anchor and leaf.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK/ca-key.pem" -out "$WORK/ca-cert.pem" -days 2 \
    -subj "/CN=uk-smoke-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout "$WORK/server-key.pem" -out "$WORK/server.csr" \
    -subj "/CN=uk-server" >/dev/null 2>&1
openssl x509 -req -in "$WORK/server.csr" \
    -CA "$WORK/ca-cert.pem" -CAkey "$WORK/ca-key.pem" -CAcreateserial \
    -out "$WORK/server-cert.pem" -days 2 \
    -extfile <(printf 'subjectAltName=DNS:uk-server\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n') \
    >/dev/null 2>&1
rm -f "$WORK/server.csr" "$WORK/ca-key.pem"

mkdir "$WORK/server" "$WORK/client"
# The server config points at /etc/uncrowned-king/server-{cert,key}.pem, and
# only "$WORK/server" is mounted there, so the TLS material must live in it.
# The client trusts the CA (not the leaf) and verifies the uk-server SAN.
cp "$WORK/server-cert.pem" "$WORK/server-key.pem" "$WORK/server/"
cp "$WORK/ca-cert.pem" "$WORK/client/ca.crt"

cat > "$WORK/server/server.toml" <<EOF
listen = "0.0.0.0:9443"
observability_listen = "127.0.0.1:9090"
cert_path = "/etc/uncrowned-king/server-cert.pem"
key_path = "/etc/uncrowned-king/server-key.pem"
policy_path = "/etc/uncrowned-king/policy.toml"

[[credentials]]
key_id = "smoke-key"
secret = "$SECRET"
EOF

cat > "$WORK/server/policy.toml" <<'EOF'
[[rules]]
action = "allow"
domain = "uk-target"
port_start = 8080
port_end = 8080
private = true
EOF

cat > "$WORK/client/client.toml" <<EOF
server_addr = "tls://uk-server:9443"
server_name = "uk-server"
ca_cert_path = "/etc/uncrowned-king/ca.crt"
key_id = "smoke-key"
secret = "$SECRET"
EOF

# The containers run as the host user (bind mounts keep host ownership), and
# the binaries refuse group/other-readable config and key material.
RUN_UID="$(id -u):$(id -g)"
chmod 600 "$WORK/server"/* "$WORK/client"/* "$WORK/server-cert.pem" "$WORK/server-key.pem"

# --- config-check (one-shot) --------------------------------------------------
docker run --rm --user "$RUN_UID" \
    -v "$WORK/server:/etc/uncrowned-king:ro" \
    "$SERVER_IMAGE" --config /etc/uncrowned-king/server.toml config-check >/dev/null
docker run --rm --user "$RUN_UID" \
    -v "$WORK/client:/etc/uncrowned-king:ro" \
    "$CLIENT_IMAGE" --config /etc/uncrowned-king/client.toml config-check >/dev/null

# --- run the relay ------------------------------------------------------------
docker run -d --name uk-server --network "$NET" --user "$RUN_UID" \
    -v "$WORK/server:/etc/uncrowned-king:ro" \
    "$SERVER_IMAGE" >/dev/null
docker run -d --name uk-client --network "$NET" --user "$RUN_UID" \
    -v "$WORK/client:/etc/uncrowned-king:ro" \
    -p 127.0.0.1:11080:1080 \
    "$CLIENT_IMAGE" --config /etc/uncrowned-king/client.toml socks5 \
    --listen 0.0.0.0:1080 --allow-non-loopback >/dev/null

# Poll until a SOCKS request round-trips (server TLS accept + carrier auth +
# flow open all happen on the first request).
deadline=$((SECONDS + 60))
body=""
while [ $SECONDS -lt $deadline ]; do
    if body="$(curl -s --max-time 5 --socks5-hostname 127.0.0.1:11080 \
            http://uk-target:8080/ 2>/dev/null)"; then
        [ "$body" = "uk-docker-smoke-ok" ] && break
    fi
    if ! docker ps --format '{{.Names}}' | grep -q '^uk-server$'; then
        echo "uk-server container exited:" >&2
        docker logs uk-server 2>&1 | tail -20 >&2 || true
        exit 1
    fi
    sleep 1
done

if [ "$body" != "uk-docker-smoke-ok" ]; then
    echo "SOCKS request through the Docker relay failed (last body: '$body')" >&2
    docker logs uk-server 2>&1 | tail -20 >&2 || true
    docker logs uk-client 2>&1 | tail -20 >&2 || true
    exit 1
fi

echo "docker smoke passed: curl -> SOCKS5 -> UK carrier -> busybox httpd"
