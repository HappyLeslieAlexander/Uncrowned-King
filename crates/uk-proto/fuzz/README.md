# Uncrowned King parser fuzz targets

These libFuzzer targets cover the strict parsers required by the protocol test
plan (whitepaper §20). They form their own cargo workspace and are excluded
from the main workspace, so they never affect the stable CI build.

Requirements: a nightly toolchain and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz
```

Run a target (from this directory or with `--fuzz-dir`):

```sh
cargo +nightly fuzz run frame_header
cargo +nightly fuzz run target_decoder
cargo +nightly fuzz run auth_payload
cargo +nightly fuzz run tcp_state
cargo +nightly fuzz run udp_state
```

| Target | Parser under test |
| --- | --- |
| `frame_header` | `FrameHeader::decode` and `Frame::decode` |
| `target_decoder` | `Target::decode` |
| `auth_payload` | `AuthChallenge::decode` and `AuthResponse::decode` |
| `tcp_state` | `TcpOpen::decode` / `TcpClose::decode` (TCP flow state inputs) |
| `udp_state` | `UdpOpen::decode` / `UdpClose::decode` (UDP flow state inputs) |

Each target asserts the invariant that strict parsing of arbitrary bytes never
panics: it may only return a decode error or a well-formed value.
