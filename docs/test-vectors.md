# Uncrowned King v1.0 Test Vectors

All bytes are hexadecimal.

> These vectors target the frozen 1.0 wire format (`protocol_revision = 2`).
> The v0.1 vectors differed only in the `AUTH_CHALLENGE` payload (which carried
> a 16-byte `session_id`) and `protocol_revision = 1`.

## 1. Varint

| Value | Encoded |
| ---: | --- |
| `37` | `25` |
| `15293` | `7b bd` |
| `494878333` | `9d 7f 3e 7d` |

## 2. Target

Domain target `example.com:443`:

```text
01 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 01 bb
```

IPv4 target `127.0.0.1:8080`:

```text
02 04 7f 00 00 01 1f 90
```

IPv6 target `[::1]:5353`:

```text
03 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 14 e9
```

## 3. Frame Header

Frame header for `TCP_DATA`, id `1`, payload length `3`:

```text
01 11 00 00 01 03
```

Full frame with payload `61 62 63`:

```text
01 11 00 00 01 03 61 62 63
```

## 4. TCP Relay Payloads

`TCP_OPEN` payload for IPv4 target `127.0.0.1:8080` with no open flags:

```text
02 04 7f 00 00 01 1f 90 00 00
```

`TCP_OPEN` payload for IPv6 target `[::1]:5353` with no open flags:

```text
03 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 14 e9 00 00
```

`TCP_CLOSE` payload for normal close:

```text
00 00
```

## 5. Auth Tag

Input:

```text
secret = "0123456789abcdef0123456789abcdef"
exporter_32 = 11 repeated 32 times
server_nonce = 22 repeated 32 times
server_time = 1700000000
server_capabilities = 01 02 03
limits = 04 05 06
client_nonce = 44 repeated 32 times
key_id = "client-a"
client_time = 1700000001
client_capabilities = "cap"
```

Expected HMAC-SHA256 tag:

```text
2c b6 09 ad 46 52 47 c1 98 54 76 0c a3 a2 24 8f
b7 e5 ea 8d 73 05 02 2b 55 6e 59 2a 71 a7 ac fc
```

## 6. Settings

`SETTINGS` payload with `max_frame_size = 65536`, `max_streams = 64`,
`max_udp_flows = 64`, `supports_udp_datagram = 0`,
`supports_udp_stream_fallback = 1`, and `protocol_revision = 2`:

```text
06 01 80 01 00 00 02 40 40 03 40 40 04 00 05 01 07 02
```

## 7. Error Frame

`POLICY_DENIED` payload:

```text
07
```

`ERROR_TARGET_UNAVAILABLE` payload:

```text
0a
```

`ERROR_TARGET_TIMEOUT` payload:

```text
0b
```

An unknown required flag example:

```text
01 11 01 00 01 00
```

The receiver must reject it with `ERROR_UNSUPPORTED_FLAG`.

## 8. Masking Prelude (docs/masking-spec.md §2)

The following fixed vectors were produced by `uk_mask::MaskKeys` itself and are
verified by `crates/uk-mask` unit tests; re-deriving them with an independent
implementation must reproduce these bytes exactly.

Input:

```text
secret = "0123456789abcdef0123456789abcdef"
key_id = "client-a"
policy = full8
identity = 0x0102030405060708
counter = 42
prelude randomness: StdRng (rand 0.8, ChaCha12) seeded with 0x0042
```

Root/auth/mask key derivation (hex of the first 8 bytes of each):

```text
root             = HMAC-SHA256(secret, "uk/1/mask/root\x01" || "client-a")
tcp_auth_key     = HMAC-SHA256(root, "uk/1/mask/tcp-auth\x01")
prelude_mask_key = HMAC-SHA256(root, "uk/1/mask/tcp-prelude-mask\x01")
tcp_c2s_key      = HMAC-SHA256(root, "uk/1/mask/tcp-c2s\x01")
tcp_s2c_key      = HMAC-SHA256(root, "uk/1/mask/tcp-s2c\x01")
udp_c2s_key      = HMAC-SHA256(root, "uk/1/mask/udp-c2s\x01")
udp_s2c_key      = HMAC-SHA256(root, "uk/1/mask/udp-s2c\x01")
```

Encoded prelude (64 bytes) and nonce (12 bytes):

```text
prelude =
  58 50 1d c3 0e 99 8b 78 74 d0 3f 54 41 c5 e0 95
  2a 8e 9c fd 89 6d 5f 68 ab c4 64 8e 46 97 c7 01
  39 cf 2a 8d c6 21 dd 14 80 50 eb 5f 8d 19 10 d3
  b9 31 44 d8 e5 1a 4f 06 eb e5 f8 a7 4b 06 31 6f
nonce  =
  6e 86 4c 49 01 23 a7 b3 0c e8 24 6e
```

Decoding `prelude` with `nonce` under the same credential yields
`identity = 0x0102030405060708`, `counter = 42`. Decoding under any other
credential (different `key_id` or `secret`), or after flipping any bit of the
prelude or nonce, must fail with the single indistinguishable rejection.
