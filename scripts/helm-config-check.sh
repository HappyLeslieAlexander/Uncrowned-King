#!/usr/bin/env bash
# Validates the Helm chart's rendered configuration against the real
# binaries' `config-check`, so a chart change that renders invalid or
# unsafe config fails CI instead of crashing pods at startup.
#
# Usage: scripts/helm-config-check.sh [binary-dir]
#   binary-dir defaults to target/debug and must contain uk-server/uk-client.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN_DIR="${1:-target/debug}"
CHART=deploy/helm/uncrowned-king
SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for bin in uk-server uk-client; do
    if [ ! -x "$BIN_DIR/$bin" ]; then
        echo "missing $BIN_DIR/$bin (build with: cargo build --locked --bin $bin)" >&2
        exit 1
    fi
done

# Materialize the TLS files the rendered configs reference.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK/tls.key" -out "$WORK/tls.crt" -days 2 \
    -subj "/CN=server.example.com" >/dev/null 2>&1
cp "$WORK/tls.crt" "$WORK/ca.crt"

RENDER_SETS=(
    --set server.existingTlsSecret=ci-tls
    --set 'server.credentials[0].id=ci-key'
    --set "server.credentials[0].secret=$SECRET"
    --set client.enabled=true
    --set client.existingCaSecret=ci-ca
    --set client.config.key_id=ci-key
    --set "client.config.secret=$SECRET"
    --set networkPolicy.enabled=true
    --set 'server.config.limits.auth_rate_limit_allowlist={198.51.100.0/24,203.0.113.7}'
)

helm template ci "$CHART" "${RENDER_SETS[@]}" > "$WORK/rendered.yaml"

# Extract one indented ConfigMap data block (e.g. `server.toml: |`).
extract_configmap_key() {
    local rendered="$1" key="$2" out="$3"
    awk -v key="  ${key}: |" '
        $0 == key { capture = 1; next }
        capture && !/^    / { capture = 0 }
        capture { sub(/^    /, ""); print }
    ' "$rendered" > "$out"
    [ -s "$out" ] || { echo "could not extract $key from rendered chart" >&2; exit 1; }
}

extract_configmap_key "$WORK/rendered.yaml" server.toml "$WORK/server.toml"
extract_configmap_key "$WORK/rendered.yaml" client.toml "$WORK/client.toml"

# Point the staged paths at this checkout's files and satisfy the pod-IP
# placeholder; credentials are staged from a Secret in production, so append
# one directly for the check.
sed -i.bak \
    -e "s|__POD_IP__|127.0.0.1|g" \
    -e "s|/etc/uncrowned-king/tls/tls.crt|$WORK/tls.crt|g" \
    -e "s|/etc/uncrowned-king/tls/tls.key|$WORK/tls.key|g" \
    -e "s|/etc/uncrowned-king/policy/policy.toml|$WORK/policy.toml|g" \
    "$WORK/server.toml"
printf '\n[[credentials]]\nkey_id = "ci-key"\nsecret = "%s"\n' "$SECRET" >> "$WORK/server.toml"

sed -i.bak \
    -e "s|__POD_IP__|127.0.0.1|g" \
    -e "s|/etc/uncrowned-king/ca/ca.crt|$WORK/ca.crt|g" \
    "$WORK/client.toml"
# Credentials are staged from a Secret in production; append them for the
# check the same way the init container would.
printf '\nkey_id = "ci-key"\nsecret = "%s"\n' "$SECRET" >> "$WORK/client.toml"

# The binaries refuse group/other-readable config and key material.
chmod 600 "$WORK"/*.toml "$WORK"/tls.key "$WORK"/tls.crt "$WORK"/ca.crt
# policy.toml comes from the rendered ConfigMap too; stage it beside the rest.
extract_configmap_key "$WORK/rendered.yaml" policy.toml "$WORK/policy.toml"
chmod 600 "$WORK/policy.toml"

"$BIN_DIR/uk-server" --config "$WORK/server.toml" config-check
"$BIN_DIR/uk-client" --config "$WORK/client.toml" config-check

# A typo in a values key must fail the render, not silently deploy defaults.
if helm template ci "$CHART" "${RENDER_SETS[@]}" \
        --set server.config.quic_lisen=0.0.0.0:9999 >/dev/null 2>"$WORK/typo.err"; then
    echo "helm template accepted the typo server.config.quic_lisen" >&2
    exit 1
fi
grep -q 'Unknown server.config field' "$WORK/typo.err" \
    || { echo "typo rejection message missing field name" >&2; exit 1; }

# Same guarantee for the client's config whitelist.
if helm template ci "$CHART" "${RENDER_SETS[@]}" \
        --set client.config.bogus_option=1 >/dev/null 2>"$WORK/client.err"; then
    echo "helm template accepted the typo client.config.bogus_option" >&2
    exit 1
fi
grep -q 'Unknown client config field' "$WORK/client.err" \
    || { echo "client typo rejection message missing field name" >&2; exit 1; }

echo "helm rendered config passed uk-server/uk-client config-check"
