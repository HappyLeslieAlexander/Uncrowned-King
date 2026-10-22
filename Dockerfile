# Multi-stage build producing minimal, non-root images for the Uncrowned King
# server and client. Build a specific image with `--target`:
#
#     docker build --target server -t uncrowned-king-server .
#     docker build --target client -t uncrowned-king-client .
#
# The runtime is a distroless image (glibc + libgcc, no shell or package
# manager) running as the non-root `nonroot` user (uid 65532).

FROM rust:1.85-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4 AS builder
WORKDIR /build
# No dependency-only cache layer: `COPY crates` below carries the workspace
# member manifests as well as the sources, so any source edit invalidates the
# build layer and dependencies are recompiled. Splitting the manifests out would
# require stubbing every member's src/ (or cargo-chef); not worth it here.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p uk-server -p uk-client

# --- server -------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS server
COPY --from=builder /build/target/release/uk-server /usr/local/bin/uk-server
USER nonroot:nonroot
# The server needs a config; mount one at /etc/uncrowned-king/server.toml. It and
# the private key must not be group/other accessible (mode 0600 on the host), or
# startup is refused.
ENTRYPOINT ["/usr/local/bin/uk-server"]
CMD ["--config", "/etc/uncrowned-king/server.toml", "serve"]

# --- client -------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS client
COPY --from=builder /build/target/release/uk-client /usr/local/bin/uk-client
USER nonroot:nonroot
# The client needs a config; mount one at /etc/uncrowned-king/client.toml. It
# must not be group/other accessible (mode 0600), or startup is refused.
#
# `--allow-non-loopback` is required because the listener binds 0.0.0.0. Inside
# the container's own network namespace that is the only address other
# containers/`-p` can reach, so it is not itself an exposure: the real exposure
# control is whether you publish the port (`-p 1080:1080`). The SOCKS5 listener
# is UNAUTHENTICATED — publish it only to a trusted network, or bind the publish
# to loopback (`-p 127.0.0.1:1080:1080`).
ENTRYPOINT ["/usr/local/bin/uk-client"]
CMD ["--config", "/etc/uncrowned-king/client.toml", "socks5", "--listen", "0.0.0.0:1080", "--allow-non-loopback"]
