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
    --set server.config.limits.max_pre_auth_connections=512
    --set server.config.limits.max_pre_auth_per_source=64
    --set server.config.limits.auth_rate_limit_global_failures=50
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

# Helper to stage rendered server.toml / client.toml and run binary config-check.
stage_and_check_server() {
    local rendered="$1" key_id="$2" out_toml="$3"
    extract_configmap_key "$rendered" server.toml "$out_toml"
    sed -i.bak \
        -e "s|__POD_IP__|127.0.0.1|g" \
        -e "s|/etc/uncrowned-king/tls/tls.crt|$WORK/tls.crt|g" \
        -e "s|/etc/uncrowned-king/tls/tls.key|$WORK/tls.key|g" \
        -e "s|/etc/uncrowned-king/policy/policy.toml|$WORK/policy.toml|g" \
        "$out_toml"
    printf '\n[[credentials]]\nkey_id = "%s"\nsecret = "%s"\n' "$key_id" "$SECRET" >> "$out_toml"
    chmod 600 "$out_toml"
    "$BIN_DIR/uk-server" --config "$out_toml" config-check
}

stage_and_check_client() {
    local rendered="$1" key_id="$2" out_toml="$3"
    extract_configmap_key "$rendered" client.toml "$out_toml"
    sed -i.bak \
        -e "s|__POD_IP__|127.0.0.1|g" \
        -e "s|/etc/uncrowned-king/ca/ca.crt|$WORK/ca.crt|g" \
        "$out_toml"
    printf '\nkey_id = "%s"\nsecret = "%s"\n' "$key_id" "$SECRET" >> "$out_toml"
    chmod 600 "$out_toml"
    "$BIN_DIR/uk-client" --config "$out_toml" config-check
}

# Validate server.config.masking (TCP+QUIC) and client.config.masking.
helm template ci "$CHART" "${RENDER_SETS[@]}" \
    --set server.config.masking.enabled=true \
    --set server.config.masking.replay_identities=2048 \
    --set server.config.masking.quic=true \
    --set server.config.masking.quic_key_id=ci-key \
    --set client.config.masking.enabled=true \
    --set client.config.masking.prelude_policy=fade \
    --set client.config.masking.quic=true > "$WORK/masked.yaml"
stage_and_check_server "$WORK/masked.yaml" "ci-key" "$WORK/server-masked.toml"
stage_and_check_client "$WORK/masked.yaml" "ci-key" "$WORK/client-masked.toml"

# Validate split masking mode (enabled=false, quic=true).
helm template ci "$CHART" "${RENDER_SETS[@]}" \
    --set server.config.masking.enabled=false \
    --set server.config.masking.quic=true \
    --set server.config.masking.quic_key_id=ci-key \
    --set client.config.masking.enabled=false \
    --set client.config.masking.quic=true > "$WORK/split.yaml"
stage_and_check_server "$WORK/split.yaml" "ci-key" "$WORK/server-split.toml"
stage_and_check_client "$WORK/split.yaml" "ci-key" "$WORK/client-split.toml"

# Validate server.existingSecret + masking.quic_key_id skips inline credential check.
helm template ci "$CHART" "${RENDER_SETS[@]}" \
    --set server.existingSecret=my-ext-secret \
    --set server.config.masking.enabled=true \
    --set server.config.masking.quic=true \
    --set server.config.masking.quic_key_id=external-key > "$WORK/ext-secret.yaml"
stage_and_check_server "$WORK/ext-secret.yaml" "external-key" "$WORK/server-ext.toml"

# Negative check: unknown masking.quic_key_id must fail closed when server.credentials are inline.
if helm template ci "$CHART" "${RENDER_SETS[@]}" \
        --set server.config.masking.enabled=true \
        --set server.config.masking.quic=true \
        --set server.config.masking.quic_key_id=missing-key >/dev/null 2>"$WORK/quic-key.err"; then
    echo "helm template accepted unknown server.config.masking.quic_key_id" >&2
    exit 1
fi
grep -q 'must name a key in server.credentials' "$WORK/quic-key.err" \
    || { echo "unknown quic_key_id rejection message missing expected text" >&2; exit 1; }

# Explicit 0 values for auth_skew_seconds and replay_identities must be rendered, not silently omitted.
helm template ci "$CHART" "${RENDER_SETS[@]}" \
    --set server.config.auth_skew_seconds=0 \
    --set server.config.masking.enabled=true \
    --set server.config.masking.replay_identities=0 > "$WORK/zero-vals.yaml"
extract_configmap_key "$WORK/zero-vals.yaml" server.toml "$WORK/server-zero.toml"
grep -q '^auth_skew_seconds = 0$' "$WORK/server-zero.toml" \
    || { echo "explicit auth_skew_seconds=0 was omitted from rendered server.toml" >&2; exit 1; }
grep -q '^replay_identities = 0$' "$WORK/server-zero.toml" \
    || { echo "explicit replay_identities=0 was omitted from rendered server.toml" >&2; exit 1; }
if stage_and_check_server "$WORK/zero-vals.yaml" "ci-key" "$WORK/server-zero-check.toml" >/dev/null 2>&1; then
    echo "uk-server config-check unexpectedly accepted explicit 0 values" >&2
    exit 1
fi

echo "helm rendered config passed uk-server/uk-client config-check"
