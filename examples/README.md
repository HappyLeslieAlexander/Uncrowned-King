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
```

Then validate the example files:

```sh
uk-server --config examples/server.toml config-check
uk-client --config examples/client.toml config-check
```

Replace the example shared secret before using these configs anywhere outside a
local throwaway environment.
