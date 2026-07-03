# Uncrowned King v0.1 Test Vectors

All bytes are hexadecimal.

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

`TCP_CLOSE` payload for normal close:

```text
00 00
```

## 5. Auth Tag

The Rust test suite fixes the secret, exporter, nonces, session id, key id,
client time, and capabilities, then validates the generated HMAC-SHA256 tag.
This keeps the source of truth executable while the v0.1 auth payload is still
settling.

## 6. Error Frame

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
