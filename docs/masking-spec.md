# Transport Masking Specification (UK/1, optional extension)

Status: implemented (Phases 1a/1b/2). This documents the wire format of the
opt-in transport masking layer defined in
[`transport-masking-plan.md`](transport-masking-plan.md). Masking is disabled
by default; when both peers enable it, the TLS/TCP and QUIC carriers are
wrapped so every byte on the wire becomes indistinguishable from random
output of a ChaCha20 keystream keyed per credential. This is **masking, not a
cryptographic boundary**: TLS/QUIC remain the sole providers of confidentiality,
integrity, and channel binding (the exporter binding of §6 of the main spec is
unaffected — the keystream sits below the TLS/QUIC records).

## 1. Key schedule

All keys derive from one credential (`key_id`, `secret`). Labels are exact
ASCII, `\x01` is a single 0x01 byte, and every HMAC is HMAC-SHA256:

```text
root             = HMAC-SHA256(secret, "uk/1/mask/root\x01"            || key_id)
tcp_auth_key     = HMAC-SHA256(root,   "uk/1/mask/tcp-auth\x01")
prelude_mask_key = HMAC-SHA256(root,   "uk/1/mask/tcp-prelude-mask\x01")
tcp_c2s_key      = HMAC-SHA256(root,   "uk/1/mask/tcp-c2s\x01")
tcp_s2c_key      = HMAC-SHA256(root,   "uk/1/mask/tcp-s2c\x01")
udp_c2s_key      = HMAC-SHA256(root,   "uk/1/mask/udp-c2s\x01")
udp_s2c_key      = HMAC-SHA256(root,   "uk/1/mask/udp-s2c\x01")
```

Servers verify TCP preludes against **every** configured credential in a
padded constant-cost loop with no early exit; the matching credential's keys
are then used for the stream. UDP endpoints carry no per-packet credential
authentication, so a masked QUIC endpoint uses exactly one *designated*
credential (`masking.quic_key_id`).

## 2. TCP prelude

A masked TCP connection begins with 64 bytes of prelude followed by 12 bytes
of random nonce `N`, then the TLS stream. Prelude layout:

| Region | Bytes | Contents |
|--------|-------|----------|
| Prefix `P` | 0..32 | policy-shaped random bytes (§3) |
| Tail | 32..64 | high bit = preserved random `H` bit; low 7 bits = payload |

The 32 × 7 = 224 tail payload bits, MSB-first, carry:

| Field | Size | Meaning |
|-------|------|---------|
| Identity | 8 | random per-client-process u64, big-endian |
| Counter | 6 | fresh per-connection u48, big-endian, in `1 ..= 2^48−1` |
| Tag | 14 | truncated HMAC, §2.1 |

### 2.1 Tag and mask

With `H` the 32 tail high bits packed MSB-first into 4 bytes:

```text
tag   = HMAC-SHA256(tcp_auth_key,     N || P || H || identity || counter)[0..14]
mask  = HMAC-SHA256(prelude_mask_key, N || P || H)
payload = (identity || counter || tag) XOR mask
```

The server reconstructs `mask`, decodes the payload, and compares the tag in
constant time (`subtle::ConstantTimeEq`). Every decode failure — wrong
credential, zero counter, malformed encoding — is reported as one
indistinguishable rejection and silently drained; nothing is written back.

### 2.2 Stream masking

After the nonce, both directions are raw ChaCha20 keystreams (no per-record
framing, no MAC): client→server keyed with `tcp_c2s_key`, server→client with
`tcp_s2c_key`, both with nonce `N`. Partial writes roll the keystream back to
the confirmed offset (`StreamCipherSeek`); the per-direction byte cap is
`2^38 − 64`.

### 2.3 Replay defense

The server keeps a FIFO registry of up to `replay_identities` (default 16 384)
entries. Each identity holds its highest committed counter plus a 1024-counter
sliding window (bit 0 = highest). A counter is admissible when it is nonzero,
above the highest, or unseen within the window; duplicates and
below-window values are rejected. **Two-phase commit**: the prelude is only
prechecked at admission; the counter commits immediately before the first
non-alert TLS record (content type ≠ 21) is flushed — which rustls only
produces after a ClientHello parsed successfully. Malformed hellos therefore
never burn counters. Registry eviction and restarts reset history;
established connections are unaffected. A jump of ≥ 1024 clears the window.

### 2.4 Prelude shaping policies

The first bytes of `P` are shaped by the client's `prelude_policy`:

| Policy | First bytes | Bits |
|--------|-------------|------|
| `fade` (default) | random boundary `a ∈ [8,12]`: bytes `< a` mapped to printable ASCII (`0x20 + x % 95`); bytes in `[a, b)`, `b ∈ [16,32]`, masked to 7 bits; rest fully random | mixed |
| `full8` | unmodified random | 8 |
| `low7` | every prelude byte masked to 7 bits | 7 |

The decoder is policy-agnostic and accepts every policy.

## 3. QUIC (UDP) masking

A masked QUIC endpoint wraps the UDP socket: every segment travels as

```text
wire segment = nonce(12) || ChaCha20(segment)
```

keyed with `udp_c2s_key` (client→server) or `udp_s2c_key` (server→client);
nonces are drawn from a CSPRNG keystream generator (32-byte seed, reseeded
before its 2^32nd byte). GSO/GRO strides carry the per-segment nonce
(`wire stride = segment size + 12`), and MTU discovery is capped at
`1452 − 12 = 1440` so masked datagrams stay within the unmasked path-MTU
budget. The QUIC layer's own AEAD, Retry, and Version Negotiation are
unaffected above the wrapper — an unauthenticated peer can never elicit a
Version Negotiation packet because the server-side filter silently drops
decrypted long headers whose version is not one of quinn's supported versions
(including version 0) before quinn sees them.

## 4. Known limits (inherited from the construction)

- The prelude tag authenticates bootstrap metadata only; it does not bind the
  ClientHello bytes.
- No forward secrecy for identity/counter metadata: a captured prelude plus a
  disclosed secret allows offline verification of candidate credentials.
- Replay history is in-memory: restarts and evictions reset it; a valid
  credential holder can churn its own window or (under a race) burn a counter
  through a competing duplicate commit — the loser is aborted before any
  response byte.
- UDP endpoint masking does not authenticate the peer per datagram; the
  designated credential's authority is endpoint-wide until the endpoint is
  reconfigured (restart).
- Masking is not traffic-analysis resistance: connection counts, timing, and
  volume remain observable.
