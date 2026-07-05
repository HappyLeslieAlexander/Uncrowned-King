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
session_id = 33 repeated 16 times
server_capabilities = 01 02 03
limits = 04 05 06
client_nonce = 44 repeated 32 times
key_id = "client-a"
client_time = 1700000001
client_capabilities = "cap"
```

Expected HMAC-SHA256 tag:

```text
52 9e d7 26 b1 af ea 54 cf ca ac 09 2b 73 e3 17
1f eb b7 e0 06 59 c1 0b b8 9c f6 86 e7 d5 3c 71
```

## 6. Settings

`SETTINGS` payload with `max_frame_size = 65536`, `max_streams = 64`,
`max_udp_flows = 64`, and `protocol_revision = 1`:

```text
04 01 80 01 00 00 02 40 40 03 40 40 07 01
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
