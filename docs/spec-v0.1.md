# Uncrowned King Protocol Specification v0.1

This document turns the whitepaper into the first implementable wire contract.
It intentionally covers only the pieces required by the initial Rust crates.

## 1. Common Encoding

All fixed-width integers are unsigned and encoded in network byte order
(big-endian). All length-prefixed byte fields use UK varint unless this
document says otherwise.

### 1.1 UK Varint

UK varint uses the QUIC variable-length integer layout:

| Prefix bits | Total bytes | Payload bits | Maximum value |
| --- | ---: | ---: | ---: |
| `00` | 1 | 6 | `63` |
| `01` | 2 | 14 | `16383` |
| `10` | 4 | 30 | `1073741823` |
| `11` | 8 | 62 | `4611686018427387903` |

Decoders must reject truncated inputs. Encoders must use the shortest legal
encoding.

## 2. Frame Header

Every UK frame begins with:

```text
u8      version
u8      type
u16     flags
varint  id
varint  length
bytes   payload
```

- `version` is `1`.
- `flags` are split into optional bits `0x0001..0x00ff` and required bits
  `0x0100..0xffff`.
- v0.1 defines no known flags. Any required flag must be rejected.
- `length` is the number of payload bytes and must not exceed the configured
  frame limit.

Frame types:

| Value | Name |
| ---: | --- |
| `0x01` | `AUTH_CHALLENGE` |
| `0x02` | `AUTH_RESPONSE` |
| `0x03` | `SETTINGS` |
| `0x04` | `PING` |
| `0x05` | `PONG` |
| `0x10` | `TCP_OPEN` |
| `0x11` | `TCP_DATA` |
| `0x12` | `TCP_CLOSE` |
| `0x20` | `UDP_OPEN` |
| `0x21` | `UDP_DATA` |
| `0x22` | `UDP_CLOSE` |
| `0x30` | `ERROR` |
| `0x31` | `POLICY_DENIED` |
| `0x32` | `RESOURCE_LIMIT` |

## 3. Target Encoding

```text
u8      addr_type
varint  host_len
bytes   host
u16     port
```

`addr_type` values:

- `0x01`: domain
- `0x02`: IPv4
- `0x03`: IPv6

Validation:

- `port` must be `1..=65535`.
- domain bytes must be valid UTF-8.
- domain byte length must be `1..=255`.
- domain must not contain ASCII control characters.
- IPv4 host length must be exactly 4.
- IPv6 host length must be exactly 16.

## 4. TCP Relay Payloads

TCP relay flow IDs are non-zero. v0.1 requires client-initiated proxy flows to
use odd IDs. Even non-zero IDs are reserved for future server-initiated flows.
Connection-scoped frames such as authentication and settings use ID `0`.

`TCP_OPEN` payload:

```text
Target target
u16    open_flags
```

v0.1 defines no non-zero `open_flags`.

`TCP_DATA` payload is uninterpreted TCP byte data.

When a `TCP_OPEN` is accepted, the server sends a zero-length `TCP_DATA` on the
same `id` as the open acknowledgement before forwarding target bytes. Rejection
uses `POLICY_DENIED`, `RESOURCE_LIMIT`, or `ERROR`, followed by `TCP_CLOSE`.

`TCP_CLOSE` payload:

```text
u16 close_code
```

`TCP_CLOSE` closes the sending direction for that flow. A peer that receives a
normal `TCP_CLOSE` may continue sending data until it also sends `TCP_CLOSE` or
the receiver's configured half-close drain window expires.

Known close codes:

| Code | Name |
| ---: | --- |
| `0` | normal close |
| `1` | generic error |

Decoders must reject unknown close codes.

## 5. Authentication Payloads

The carrier supplies a 32-byte TLS/QUIC exporter binding. Until carriers are
implemented, tests pass this value explicitly.

`AUTH_CHALLENGE` payload:

```text
bytes[32] server_nonce
u64       server_time
bytes[16] session_id
varint    server_capabilities_len
bytes     server_capabilities
varint    limits_len
bytes     limits
```

`AUTH_RESPONSE` payload:

```text
varint    key_id_len
bytes     key_id
bytes[32] client_nonce
u64       client_time
varint    client_capabilities_len
bytes     client_capabilities
bytes[32] tag
```

`key_id_len` must be `1..=64`. Shared secrets are local configuration, never
sent on the wire, and must contain at least 32 bytes of secret material.

`tag` is:

```text
HMAC-SHA256(
  secret,
  "UK-AUTH-v1" ||
  exporter_32 ||
  server_nonce ||
  client_nonce ||
  session_id ||
  key_id ||
  client_time_be ||
  client_capabilities
)
```

## 6. SETTINGS Payload

v0.1 settings use repeated key/value pairs:

```text
varint setting_count
repeat setting_count:
  varint key
  varint value
```

Known keys:

| Key | Name |
| ---: | --- |
| `1` | `max_frame_size` |
| `2` | `max_streams` |
| `3` | `max_udp_flows` |
| `4` | `supports_udp_datagram` |
| `5` | `supports_udp_stream_fallback` |
| `6` | `idle_timeout_seconds` |
| `7` | `protocol_revision` |

Unknown optional settings may be ignored. Required setting semantics will be
added after v0.1. Decoders must reject trailing bytes after the declared
setting pairs.

## 7. Error Codes

`ERROR`, `POLICY_DENIED`, and `RESOURCE_LIMIT` payloads carry one coarse code:

```text
varint error_code
```

| Code | Name |
| ---: | --- |
| `1` | `ERROR_UNSUPPORTED_VERSION` |
| `2` | `ERROR_UNSUPPORTED_FLAG` |
| `3` | `ERROR_OVERSIZED_FRAME` |
| `4` | `ERROR_TRUNCATED_FRAME` |
| `5` | `ERROR_INVALID_TARGET` |
| `6` | `ERROR_AUTH_FAILED` |
| `7` | `ERROR_POLICY_DENIED` |
| `8` | `ERROR_RESOURCE_LIMIT` |
| `9` | `ERROR_PROTOCOL` |
| `10` | `ERROR_TARGET_UNAVAILABLE` |
| `11` | `ERROR_TARGET_TIMEOUT` |
