# Docker Example

This example is the Docker-oriented counterpart to `examples/`. It uses
container-routable listen addresses and mounts the whole configuration
directory so the certificate, private key, policy, and shared secret are all
present.

## 1. Generate a certificate

`uk-client` verifies the server certificate against the CA and server name.
For a local demo a self-signed certificate with `localhost` SAN is enough:

```sh
cd examples/docker
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server-cert.pem -days 30 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
chmod 600 server-key.pem server-cert.pem
```

Replace the placeholder shared secret in `server.toml` and `client.toml` before
using this outside a throwaway environment, and keep both files mode `0600`.

## 2. Run the server

On Linux, bind-mount UID ownership is preserved. The image runs as UID 65532
by default, so either run as the host file owner:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/etc/uncrowned-king:ro" \
  -p 9443:9443/tcp -p 9443:9443/udp \
  uncrowned-king-server
```

or give the files to the image user:

```sh
sudo chown -R 65532:65532 examples/docker
docker run --rm \
  -v "$PWD:/etc/uncrowned-king:ro" \
  -p 9443:9443/tcp -p 9443:9443/udp \
  uncrowned-king-server
```

Do **not** chmod the config to 0644 to work around permissions: the server
rejects group/other-readable config and private-key files.

## 3. Run the client

The client config points at the Compose service name `server`; when running
standalone, set `server_addr` to a host reachable from the container (for
example `quic://host.docker.internal:9443` on Docker Desktop, or the host's
bridge address on Linux).

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/etc/uncrowned-king:ro" \
  -p 127.0.0.1:1080:1080 \
  uncrowned-king-client
```

The image command binds `0.0.0.0:1080` inside the container and passes
`--allow-non-loopback`; publishing only to `127.0.0.1` keeps the unauthenticated
SOCKS listener off other host interfaces.

## 4. Compose

```sh
docker compose -f examples/docker/docker-compose.yml up --build
```

Then test through the proxy:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

The demo policy allows only `example.com:443`; adjust `policy.toml` for real
targets. The `observability_listen` endpoints are loopback-only inside each
container and are intentionally not published.
