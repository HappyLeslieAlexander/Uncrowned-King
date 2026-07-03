# Uncrowned King: A Practical Secure Proxy Protocol

## Abstract

Uncrowned King, abbreviated as UK, is a secure proxy protocol designed for high-performance TCP and UDP forwarding over standard encrypted transports. UK runs over TLS 1.3, QUIC, HTTP/2, or WebSocket-compatible streams, and provides authenticated session establishment, multiplexed TCP streams, UDP flow forwarding, policy enforcement, resource control, and structured observability.

UK does not attempt to invent new cryptography. It uses existing transport security and adds a compact authenticated proxy layer above it. The goal is a protocol that is simple enough to implement correctly, fast enough for production traffic, and strict enough to survive hostile input and unreliable networks.

## 1. Introduction

A practical proxy protocol must solve more than forwarding bytes. It must authenticate clients before target access, prevent replay, support TCP and UDP, avoid uncontrolled resource growth, survive packet loss and transport failure, and expose enough telemetry for operators to debug production incidents.

UK is designed around four principles:

1. Use standard encrypted transports.
2. Authenticate before any target connection.
3. Encode targets and frames strictly.
4. Treat resource limits as part of the protocol.

UK is not a single transport. It is a proxy session protocol that may run over several transports.

## 2. Design Goals

UK aims to provide:

- Encrypted proxy transport over standard TLS 1.3 and QUIC.
- TCP relay with multiplexed streams.
- UDP relay with QUIC DATAGRAM when available.
- UDP-over-stream fallback when datagrams are unavailable.
- Session authentication bound to the underlying TLS or QUIC connection.
- Explicit resource limits for pre-authentication and post-authentication states.
- Structured target encoding instead of raw `host:port` strings.
- Server-side policy enforcement for target access.
- Versioned frames and forward-compatible capability negotiation.
- Predictable failure behavior.

UK does not provide:

- Its own transport encryption.
- Anonymous routing.
- Peer-to-peer discovery.
- Built-in payment, reputation, or account systems.
- A management API. Management is an implementation concern.

## 3. Transport Model

UK defines one session protocol and multiple carriers.

### 3.1 Carriers

The initial version supports four carriers:

| Carrier | Name | Purpose |
|---|---|---|
| QUIC | `uk-quic` | Preferred transport for low latency, multiplexing, and UDP datagrams |
| TLS/TCP | `uk-tls` | Stable fallback for TCP-heavy networks |
| HTTP/2 stream | `uk-h2` | Deployment behind standard HTTP infrastructure |
| WebSocket over TLS | `uk-ws` | Compatibility fallback |

All carriers must provide confidentiality and integrity. Plaintext UK is invalid.

### 3.2 ALPN

Native carriers should use:

```text
uk/1
```

HTTP/2 and WebSocket deployments may identify UK inside the encrypted HTTP request after normal TLS negotiation.

### 3.3 0-RTT

UK application data must not be accepted through TLS or QUIC 0-RTT. Authentication and proxy requests must be processed only after the transport handshake completes.

## 4. Connection State Machine

Every connection follows this state machine:

```text
CONNECTING
  -> TRANSPORT_READY
  -> AUTH_CHALLENGE
  -> AUTHENTICATED
  -> RELAYING
  -> CLOSING
```

No DNS lookup, outbound TCP dial, outbound UDP socket creation, or target policy decision may occur before `AUTHENTICATED`.

Authentication failure transitions directly to `CLOSING`.

## 5. Authentication

UK uses challenge-response authentication with TLS exporter binding.

### 5.1 Keys

Each credential has:

```text
key_id: opaque identifier, 1..=64 bytes
secret: 32 bytes or longer random secret
status: active | disabled | retired
not_before: optional timestamp
not_after: optional timestamp
policy_group: optional policy group
```

The client sends `key_id`, never the secret.

### 5.2 Challenge

Server sends:

```text
AUTH_CHALLENGE {
  server_nonce: 32 bytes
  server_time: u64 unix seconds
  session_id: 16 bytes
  server_capabilities: CapabilityList
  limits: ServerLimits
}
```

### 5.3 Response

Client sends:

```text
AUTH_RESPONSE {
  key_id: bytes
  client_nonce: 32 bytes
  client_time: u64 unix seconds
  client_capabilities: CapabilityList
  tag: 32 bytes
}
```

The tag is:

```text
HMAC-SHA256(
  secret,
  "UK-AUTH-v1" ||
  tls_exporter("EXPORTER-UK-v1", 32) ||
  server_nonce ||
  client_nonce ||
  session_id ||
  key_id ||
  client_time ||
  client_capabilities
)
```

The server must reject:

- Unknown `key_id`
- Disabled or expired key
- Invalid HMAC
- Clock skew outside configured window
- Reused nonce within replay cache window
- Missing required capabilities

## 6. Frame Format

All UK frames use a compact binary format.

```text
struct Frame {
  u8      version;
  u8      type;
  u16     flags;
  varint  id;
  varint  length;
  bytes   payload;
}
```

`version` is `1`.

`flags` are split into optional and required ranges. If an unknown required flag is present, the receiver must close the connection with `ERROR_UNSUPPORTED_FLAG`.

### 6.1 Frame Types

```text
0x01 AUTH_CHALLENGE
0x02 AUTH_RESPONSE
0x03 SETTINGS
0x04 PING
0x05 PONG

0x10 TCP_OPEN
0x11 TCP_DATA
0x12 TCP_CLOSE

0x20 UDP_OPEN
0x21 UDP_DATA
0x22 UDP_CLOSE

0x30 ERROR
0x31 POLICY_DENIED
0x32 RESOURCE_LIMIT
```

### 6.2 Frame Limits

Default limits:

```text
max_frame_size = 65536 bytes
max_pre_auth_bytes = 4096 bytes
max_target_host_len = 255 bytes
max_key_id_len = 64 bytes
```

Implementations may reduce these limits. They must not silently accept frames above configured limits.

## 7. Target Encoding

UK does not use raw `host:port`.

Targets are encoded as:

```text
Target {
  addr_type: u8
  host_len: varint
  host: bytes
  port: u16
}
```

`addr_type` values:

```text
0x01 domain
0x02 ipv4
0x03 ipv6
```

Validation rules:

- `port` must be `1..65535`.
- Domain must be valid UTF-8.
- Domain must not contain ASCII control characters.
- Domain length must be `1..255`.
- IPv4 host length must be 4 bytes.
- IPv6 host length must be 16 bytes.
- The server must apply policy before dialing.
- If a domain resolves to a forbidden IP range, the connection must be rejected.

## 8. Policy Enforcement

Authentication proves identity. Policy grants access.

A server policy may match:

- `key_id`
- policy group
- target address type
- domain suffix
- CIDR range
- port range
- carrier type
- time window
- connection count
- traffic direction

Domain suffix matches are DNS label-boundary matches. For example,
`example.com` matches `example.com` and `api.example.com`, but not
`badexample.com`.

Domain predicates must not be empty or contain ASCII control characters.
Policy `key_id` predicates use the same `1..=64` byte bound as authentication
key identifiers. Policy group predicates must not be empty or contain ASCII
control characters.

Policy actions must be explicit `allow` or `deny`; unknown action strings are
configuration errors.

Example policy:

```text
allow group=default domain_suffix=.example.com ports=443,8443
allow group=ops cidr=10.20.0.0/16 ports=22,5432
deny  ip=169.254.169.254
deny  private=true unless group=internal
```

Policy denial returns `POLICY_DENIED` with a generic reason code. Detailed rule IDs remain in server logs.

## 9. TCP Relay

A TCP relay starts with `TCP_OPEN`.

```text
TCP_OPEN {
  target: Target
  open_flags: u16
}
```

If accepted, both peers exchange `TCP_DATA` frames using the same `id`.

```text
TCP_DATA {
  bytes payload
}
```

Closing is explicit:

```text
TCP_CLOSE {
  close_code: u16
}
```

TCP half-close should be supported. After one side closes, the other side receives a configurable drain window, default `30s` (`tcp_half_close_timeout_seconds`).

## 10. UDP Relay

UDP relay uses flow IDs.

```text
UDP_OPEN {
  target: Target
}
```

UDP payload:

```text
UDP_DATA {
  bytes payload
}
```

UDP close:

```text
UDP_CLOSE {
  close_code: u16
}
```

In QUIC carrier mode, `UDP_DATA` should use QUIC DATAGRAM when available. If unavailable, it may be carried as stream frames.

Default UDP limits:

```text
max_udp_flows_per_session = 128
udp_idle_timeout = 120s
max_udp_payload = 65507 bytes, further limited by carrier MTU
```

The server must close idle UDP flows and release sockets.

## 11. Multiplexing

Each TCP stream or UDP flow uses a unique `id`.

Recommended ID allocation:

```text
client initiated: odd IDs
server initiated: even IDs
```

UK v1 only requires client-initiated proxy flows. Server-initiated flows are reserved for future use.

## 12. Flow Control

UK relies on QUIC or TCP for transport flow control, but must also enforce application limits.

Required limits:

```text
max_streams_per_session
max_udp_flows_per_session
max_buffered_bytes_per_session
max_buffered_bytes_per_flow
max_outbound_dials_per_session
```

Capacity limits must be greater than zero. Timeout fields may use zero only
when the implementation explicitly documents zero as disabling that timeout.

When limits are exceeded, the server returns `RESOURCE_LIMIT` or closes the offending flow.

## 13. Performance Requirements

A production implementation should use:

- Reusable buffers, default 32 KiB or 64 KiB.
- Per-direction rate counters.
- Batched writes where possible.
- Connection pooling on the client.
- Separate carrier connections for latency-sensitive and bulk traffic.
- QUIC DATAGRAM for UDP when available.
- Adaptive fallback when a carrier fails.

Recommended client behavior:

```text
Maintain 1 warm control connection.
Maintain up to N active carrier connections.
Prefer QUIC when RTT and loss are acceptable.
Fallback to TLS/TCP or WebSocket when QUIC is unavailable.
Avoid putting bulk download and latency-sensitive streams on the same TLS/TCP carrier.
```

## 14. Failure Handling

UK failure behavior must be predictable.

Authentication errors:

```text
close connection
log locally
do not expose detailed reason to client
```

Policy errors:

```text
send POLICY_DENIED with generic reason
close only the affected flow
```

Target dial errors:

```text
send ERROR with coarse network code
close only the affected flow
```

Protocol errors:

```text
close connection
```

## 15. Observability

UK implementations must emit structured events.

Recommended events:

```text
auth.success
auth.failure
policy.denied
tcp.open
tcp.close
udp.open
udp.close
carrier.fallback
resource.limit
rate.limit
protocol.error
```

All client-controlled fields must be escaped. Logs must never contain:

- shared secrets
- auth tags
- raw unescaped targets
- private key material
- full connection URLs containing credentials

## 16. Security Considerations

UK assumes the underlying TLS or QUIC implementation is secure and correctly configured.

Important requirements:

- TLS 1.3 minimum.
- No plaintext UK.
- No 0-RTT UK data.
- Authentication bound to TLS exporter.
- Replay cache for recent nonce pairs.
- Constant-time HMAC comparison.
- Strict frame length checks.
- Strict target validation.
- Policy check before DNS result use and before dialing.
- Resource limits before and after authentication.
- Escaped structured logs.

## 17. Recommended Module Architecture

Server modules:

```text
listener
carrier
auth
session
frame_codec
policy
dialer
relay_tcp
relay_udp
limits
metrics
logger
config
```

Client modules:

```text
config
carrier_selector
auth
session
frame_codec
tcp_adapter
udp_adapter
connection_pool
fallback
metrics
```

Each module should have narrow responsibility. The frame codec must not dial targets. The policy engine must not parse TLS. The relay layer must not authenticate clients.

## 18. Versioning

Major versions use ALPN:

```text
uk/1
uk/2
```

Minor features use `SETTINGS`.

A peer may ignore unknown optional settings. A peer must reject unknown required settings.

`SETTINGS` should include:

```text
max_frame_size
max_streams
max_udp_flows
supports_udp_datagram
supports_udp_stream_fallback
idle_timeout
protocol_revision
```

Peers must fail the session when `protocol_revision` is missing or unsupported.
Advertised `max_frame_size` and `max_streams` values must be greater than zero.

## 19. Minimum Viable Implementation

UK v1 should implement:

1. TLS/TCP carrier.
2. QUIC carrier.
3. Challenge-response HMAC authentication.
4. TLS exporter binding.
5. TCP relay.
6. UDP over QUIC DATAGRAM.
7. UDP-over-stream fallback.
8. Strict target encoding.
9. Server-side policy.
10. Resource limits.
11. Structured logs.
12. Carrier fallback on the client.

HTTP/2 and WebSocket carriers may be implemented after the native carriers.

## 20. Test Plan

Required tests:

- Valid authentication.
- Invalid key.
- Invalid HMAC.
- Replayed nonce.
- Expired timestamp.
- Unknown required flag.
- Oversized frame.
- Truncated frame.
- Invalid target.
- Policy denied target.
- TCP relay success.
- TCP half-close.
- UDP flow success.
- UDP idle cleanup.
- Resource limit exceeded.
- Carrier fallback.
- Log escaping.

Fuzz targets:

- frame header parser
- target decoder
- auth payload decoder
- TCP state machine
- UDP flow state machine

## 21. Conclusion

Uncrowned King is a practical secure proxy protocol built on standard encrypted transports. Its design is intentionally conservative: simple frames, strict parsing, authenticated sessions, explicit policy, bounded resources, and measurable behavior.

The protocol succeeds if an implementation can be reviewed, tested, deployed, and operated without hidden assumptions. UK should be fast, but not vague; flexible, but not loose; powerful, but not careless.
