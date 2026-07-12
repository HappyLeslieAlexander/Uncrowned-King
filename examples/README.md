# Local Configuration Examples

These files are for local development only. Generate a self-signed certificate
before running `config-check` or starting the example server:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/server-key.pem \
  -out examples/server-cert.pem \
  -days 30 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 examples/server-key.pem examples/server.toml examples/client.toml
```

Then validate the example files:

```sh
uk-server --config examples/server.toml config-check
uk-client --config examples/client.toml config-check
```

Relative file paths inside these TOML files are resolved from the `examples/`
directory because that is where the config files live.

Start the local demo services in separate terminals:

```sh
uk-server --config examples/server.toml serve
uk-client --config examples/client.toml socks5 --listen 127.0.0.1:1080
```

Both long-running commands stop gracefully on Ctrl+C or SIGTERM.

Replace the example shared secret before using these configs anywhere outside a
local throwaway environment.

Client `server_addrs` entries are tried after `server_addr`; each configured
server endpoint gets its own `handshake_timeout_seconds` budget.

The example limits enable UDP relay with `max_udp_flows = 64` and close
per-target UDP flows after `udp_flow_idle_timeout_seconds = 120` seconds with no
datagrams relayed in either direction.

The example policy denies private resolved addresses before allowing
`example.com` traffic. Keep deny rules before broad allow rules when adapting it.
Known cloud metadata service IPs are hard-denied by the policy engine before
those ordered rules are evaluated.
