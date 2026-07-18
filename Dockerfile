# Multi-stage build producing minimal, non-root images for the Uncrowned King
# server and client. Build a specific image with `--target`:
#
#     docker build --target server -t uncrowned-king-server .
#     docker build --target client -t uncrowned-king-client .
#
# The runtime is a distroless image (glibc + libgcc, no shell or package
# manager) running as the non-root `nonroot` user (uid 65532).

FROM rust:1.85-bookworm AS builder
WORKDIR /build
# Cache dependency compilation across source-only changes.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p uk-server -p uk-client

# --- server -------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS server
COPY --from=builder /build/target/release/uk-server /usr/local/bin/uk-server
USER nonroot:nonroot
# The server needs a config; mount one at /etc/uncrowned-king/server.toml.
ENTRYPOINT ["/usr/local/bin/uk-server"]
CMD ["--config", "/etc/uncrowned-king/server.toml", "serve"]

# --- client -------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS client
COPY --from=builder /build/target/release/uk-client /usr/local/bin/uk-client
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/uk-client"]
CMD ["--config", "/etc/uncrowned-king/client.toml", "socks5", "--listen", "0.0.0.0:1080"]
