"""Pure-Python wire protocol helpers, probes, SOCKS5 client, and timing proxies
for Uncrowned King opaque-box E2E hardening tests.

Zero external dependencies: uses only Python 3 stdlib.
"""

from dataclasses import dataclass, field
from enum import Enum
import errno
import hashlib
import hmac
import os
import random
import selectors
import socket
import struct
import threading
import time
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# ---------------------------------------------------------------------------
# Wire constants (matching crates/uk-mask, uk-proto, uk-auth)
# ---------------------------------------------------------------------------

PRELUDE_LEN = 64
NONCE_LEN = 12
WIRE_PRELUDE_LEN = PRELUDE_LEN + NONCE_LEN  # 76 bytes
PREFIX_LEN = 32
TAIL_LEN = 32
IDENTITY_LEN = 8
COUNTER_LEN = 6
TAG_LEN = 14
TAIL_PAYLOAD_LEN = 28  # 224 bits = 32 * 7 bits
MAX_COUNTER = (1 << 48) - 1
REPLAY_WINDOW = 1024
STREAM_LIMIT = (1 << 38) - 64
MAX_WRITE_CHUNK = 64 * 1024

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
ALPN_UK1 = b"uk/1"

# Valid X25519 public point (RFC 7748 Alice public key) for TLS 1.3 ClientHello key_share
_DEFAULT_X25519_PUB = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)


# ---------------------------------------------------------------------------
# Pure-Python RFC 8439 ChaCha20 (starting at block counter 0)
# ---------------------------------------------------------------------------

def _rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _qround(s: List[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Compute a 64-byte RFC 8439 ChaCha20 keystream block."""
    if len(key) != 32:
        raise ValueError(f"ChaCha20 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"ChaCha20 nonce must be 12 bytes, got {len(nonce)}")
    state = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        *struct.unpack("<8I", key),
        counter & 0xFFFFFFFF,
        *struct.unpack("<3I", nonce),
    ]
    w = state.copy()
    for _ in range(10):
        _qround(w, 0, 4, 8, 12)
        _qround(w, 1, 5, 9, 13)
        _qround(w, 2, 6, 10, 14)
        _qround(w, 3, 7, 11, 15)
        _qround(w, 0, 5, 10, 15)
        _qround(w, 1, 6, 11, 12)
        _qround(w, 2, 7, 8, 13)
        _qround(w, 3, 4, 9, 14)
    return struct.pack(
        "<16I", *(((w[i] + state[i]) & 0xFFFFFFFF) for i in range(16))
    )


class ChaCha20Stream:
    """IETF ChaCha20 byte-stream cipher starting at block counter 0."""

    def __init__(self, key: bytes, nonce: bytes, initial_offset: int = 0) -> None:
        if len(key) != 32:
            raise ValueError(f"key must be 32 bytes, got {len(key)}")
        if len(nonce) != 12:
            raise ValueError(f"nonce must be 12 bytes, got {len(nonce)}")
        if initial_offset < 0:
            raise ValueError("initial_offset must be non-negative")
        self.key = bytes(key)
        self.nonce = bytes(nonce)
        self.offset = initial_offset
        self._cached_counter: Optional[int] = None
        self._cached_block: bytes = b""

    def seek(self, offset: int) -> None:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        self.offset = offset

    def _block(self, counter: int) -> bytes:
        if self._cached_counter != counter:
            self._cached_block = chacha20_block(self.key, counter, self.nonce)
            self._cached_counter = counter
        return self._cached_block

    def apply(self, data: bytes) -> bytes:
        """XOR data with the ChaCha20 keystream starting at self.offset."""
        if not data:
            return b""
        out = bytearray(len(data))
        pos = 0
        total = len(data)
        while pos < total:
            blk_idx = self.offset // 64
            blk_off = self.offset % 64
            blk = self._block(blk_idx)
            take = min(64 - blk_off, total - pos)
            for i in range(take):
                out[pos + i] = data[pos + i] ^ blk[blk_off + i]
            self.offset += take
            pos += take
        return bytes(out)


# ---------------------------------------------------------------------------
# MaskKeys KDF & 76-byte Prelude Codec
# ---------------------------------------------------------------------------

def _hmac256(key: bytes, *parts: bytes) -> bytes:
    m = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        m.update(part)
    return m.digest()


@dataclass(frozen=True)
class MaskKeys:
    """Derived transport masking keys for a single credential."""

    key_id: bytes
    auth_key: bytes
    prelude_mask_key: bytes
    tcp_c2s: bytes
    tcp_s2c: bytes
    udp_c2s: bytes
    udp_s2c: bytes


def derive_mask_keys(
    key_id: Union[str, bytes], secret: Union[str, bytes]
) -> MaskKeys:
    """Derive UK masking keys matching crates/uk-mask/src/lib.rs:MaskKeys::derive."""
    kid = key_id.encode("utf-8") if isinstance(key_id, str) else bytes(key_id)
    sec = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    root = _hmac256(sec, b"uk/1/mask/root\x01", kid)
    return MaskKeys(
        key_id=kid,
        auth_key=_hmac256(root, b"uk/1/mask/tcp-auth\x01"),
        prelude_mask_key=_hmac256(root, b"uk/1/mask/tcp-prelude-mask\x01"),
        tcp_c2s=_hmac256(root, b"uk/1/mask/tcp-c2s\x01"),
        tcp_s2c=_hmac256(root, b"uk/1/mask/tcp-s2c\x01"),
        udp_c2s=_hmac256(root, b"uk/1/mask/udp-c2s\x01"),
        udp_s2c=_hmac256(root, b"uk/1/mask/udp-s2c\x01"),
    )


def _generate_filler(policy: str) -> bytearray:
    raw = bytearray(os.urandom(PRELUDE_LEN))
    if policy == "fade":
        printable_end = random.randint(8, 12)
        seven_bit_end = random.randint(16, 32)
        for i in range(printable_end):
            raw[i] = 0x20 + (raw[i] % (0x7E - 0x20 + 1))
        for i in range(printable_end, seven_bit_end):
            raw[i] &= 0x7F
    elif policy == "full8":
        pass
    elif policy == "low7":
        for i in range(PRELUDE_LEN):
            raw[i] &= 0x7F
    elif policy == "zero":
        raw = bytearray(PRELUDE_LEN)
    else:
        raise ValueError(f"unknown prelude policy: {policy!r}")
    return raw


def _pack_high_bits(tail: Sequence[int]) -> bytes:
    high_bits = bytearray(4)
    for idx in range(TAIL_LEN):
        high_bits[idx // 8] |= (tail[idx] & 0x80) >> (7 - (idx % 8))
    return bytes(high_bits)


def encode_prelude(
    keys: MaskKeys,
    identity: int,
    counter: int,
    policy: str = "fade",
    nonce: Optional[bytes] = None,
    high_bits_override: Optional[Union[bytes, int]] = None,
    allow_zero_counter: bool = False,
) -> Tuple[bytes, bytes]:
    """Encode a 76-byte UK client prelude (64B prelude || 12B nonce).

    Args:
        keys: Derived MaskKeys for the credential.
        identity: 64-bit unsigned identity.
        counter: 48-bit counter in [1, MAX_COUNTER] (or 0 if allow_zero_counter=True).
        policy: "fade", "full8", "low7", or "zero".
        nonce: Optional 12-byte nonce (random if None).
        high_bits_override: Optional 32B tail bit7 mask, 4B packed high bits,
            or int (0x00 / 0x80) applied to all 32 tail bytes.
        allow_zero_counter: Allow crafting a valid HMAC tag for counter=0
            (for testing T2-R5-01 tag-before-report zero-counter rejection).

    Returns:
        Tuple of (wire_76_bytes, nonce_12_bytes).
    """
    if not (0 <= identity <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("identity out of u64 range")
    min_ctr = 0 if allow_zero_counter else 1
    if not (min_ctr <= counter <= MAX_COUNTER):
        raise ValueError(f"counter {counter} out of [{min_ctr}, {MAX_COUNTER}]")

    if nonce is None:
        nonce_bytes = os.urandom(NONCE_LEN)
    else:
        if len(nonce) != NONCE_LEN:
            raise ValueError(f"nonce must be {NONCE_LEN} bytes")
        nonce_bytes = bytes(nonce)

    raw = _generate_filler(policy)
    prefix = bytes(raw[:PREFIX_LEN])
    tail = bytearray(raw[PREFIX_LEN:])

    if high_bits_override is not None:
        if isinstance(high_bits_override, int):
            hb = high_bits_override & 0x80
            for idx in range(TAIL_LEN):
                tail[idx] = (tail[idx] & 0x7F) | hb
        elif len(high_bits_override) == TAIL_LEN:
            for idx in range(TAIL_LEN):
                tail[idx] = (tail[idx] & 0x7F) | (high_bits_override[idx] & 0x80)
        elif len(high_bits_override) == 4:
            for idx in range(TAIL_LEN):
                bit = (high_bits_override[idx // 8] >> (7 - (idx % 8))) & 1
                tail[idx] = (tail[idx] & 0x7F) | (bit << 7)
        else:
            raise ValueError(
                "high_bits_override must be int, 4 bytes, or 32 bytes"
            )

    high_bits = _pack_high_bits(tail)
    id_be = struct.pack(">Q", identity)
    ctr_be = struct.pack(">Q", counter)[2:]
    tag = _hmac256(
        keys.auth_key, nonce_bytes, prefix, high_bits, id_be, ctr_be
    )[:TAG_LEN]
    payload = id_be + ctr_be + tag
    mask = _hmac256(keys.prelude_mask_key, nonce_bytes, prefix, high_bits)[:TAIL_PAYLOAD_LEN]
    masked = bytes(payload[i] ^ mask[i] for i in range(TAIL_PAYLOAD_LEN))

    for bit_idx in range(224):
        bit = (masked[bit_idx // 8] >> (7 - (bit_idx % 8))) & 1
        grp = bit_idx // 7
        pos = bit_idx % 7
        bit_mask = 1 << (6 - pos)
        tail[grp] = (tail[grp] & (~bit_mask & 0xFF)) | (bit << (6 - pos))

    return prefix + bytes(tail) + nonce_bytes, nonce_bytes


def decode_prelude(
    keys_list: Union[MaskKeys, Sequence[MaskKeys]],
    wire76: bytes,
) -> Tuple[MaskKeys, int, int, bytes]:
    """Decode and verify a 76-byte wire prelude against one or more MaskKeys.

    Returns (matched_keys, identity, counter, nonce) or raises ValueError.
    """
    if len(wire76) != WIRE_PRELUDE_LEN:
        raise ValueError(f"expected {WIRE_PRELUDE_LEN} bytes, got {len(wire76)}")
    candidates = [keys_list] if isinstance(keys_list, MaskKeys) else list(keys_list)
    if not candidates:
        raise ValueError("no candidate keys supplied")

    prefix = wire76[:PREFIX_LEN]
    tail = wire76[PREFIX_LEN:PRELUDE_LEN]
    nonce = wire76[PRELUDE_LEN:WIRE_PRELUDE_LEN]
    high_bits = _pack_high_bits(tail)

    masked = bytearray(TAIL_PAYLOAD_LEN)
    for bit_idx in range(224):
        grp = bit_idx // 7
        pos = bit_idx % 7
        bit = (tail[grp] >> (6 - pos)) & 1
        if bit:
            masked[bit_idx // 8] |= 1 << (7 - (bit_idx % 8))

    matched: Optional[Tuple[MaskKeys, int, int]] = None
    for keys in candidates:
        mask = _hmac256(keys.prelude_mask_key, nonce, prefix, high_bits)[:TAIL_PAYLOAD_LEN]
        payload = bytes(masked[i] ^ mask[i] for i in range(TAIL_PAYLOAD_LEN))
        id_be = payload[:IDENTITY_LEN]
        ctr_be = payload[IDENTITY_LEN : IDENTITY_LEN + COUNTER_LEN]
        tag = payload[IDENTITY_LEN + COUNTER_LEN : TAIL_PAYLOAD_LEN]
        expected_tag = _hmac256(
            keys.auth_key, nonce, prefix, high_bits, id_be, ctr_be
        )[:TAG_LEN]
        tag_ok = hmac.compare_digest(tag, expected_tag)
        identity = struct.unpack(">Q", id_be)[0]
        counter = struct.unpack(">Q", b"\x00\x00" + ctr_be)[0]
        if tag_ok and counter != 0 and matched is None:
            matched = (keys, identity, counter)

    if matched is None:
        raise ValueError("prelude rejected")
    return matched[0], matched[1], matched[2], nonce


# ---------------------------------------------------------------------------
# Pure-Python TLS 1.3 ClientHello Record Builder & Adversarial Variants
# ---------------------------------------------------------------------------

def _u16_vec(items: Iterable[int]) -> bytes:
    body = b"".join(struct.pack(">H", x) for x in items)
    return struct.pack(">H", len(body)) + body


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def split_tls_records(
    handshake_bytes: bytes,
    content_type: int = 0x16,
    record_version: int = 0x0301,
    max_record_payload: int = 16384,
) -> bytes:
    """Split a TLS handshake message into valid <=16 KiB TLS records."""
    if not (1 <= max_record_payload <= 16384):
        raise ValueError("max_record_payload must be in 1..=16384")
    out = bytearray()
    for off in range(0, len(handshake_bytes), max_record_payload):
        chunk = handshake_bytes[off : off + max_record_payload]
        out += struct.pack(">BHH", content_type, record_version, len(chunk))
        out += chunk
    return bytes(out)


def _build_client_hello_handshake(
    server_name: str = "localhost",
    alpn_protocols: Sequence[bytes] = (ALPN_UK1,),
    supported_versions: Sequence[int] = (0x0304,),
    cipher_suites: Sequence[int] = (0x1301, 0x1302, 0x1303),
    include_key_share: bool = True,
    padding_len: Optional[int] = None,
    legacy_session_id: Optional[bytes] = None,
) -> bytes:
    sni_bytes = server_name.encode("utf-8")
    sni_entry = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
    sni_ext = _ext(0x0000, struct.pack(">H", len(sni_entry)) + sni_entry)

    groups_ext = _ext(0x000A, _u16_vec((0x001D, 0x0017)))
    sig_alg_ext = _ext(
        0x000D, _u16_vec((0x0403, 0x0804, 0x0807, 0x0401))
    )

    exts = bytearray()
    exts += sni_ext
    exts += groups_ext
    exts += sig_alg_ext

    if alpn_protocols:
        alpn_body = b"".join(bytes([len(p)]) + p for p in alpn_protocols)
        exts += _ext(0x0010, struct.pack(">H", len(alpn_body)) + alpn_body)

    if supported_versions:
        sv_body = b"".join(struct.pack(">H", v) for v in supported_versions)
        exts += _ext(0x002B, bytes([len(sv_body)]) + sv_body)

    if include_key_share:
        ks_entry = struct.pack(">HH", 0x001D, len(_DEFAULT_X25519_PUB)) + _DEFAULT_X25519_PUB
        exts += _ext(0x0033, struct.pack(">H", len(ks_entry)) + ks_entry)

    if padding_len is not None:
        if padding_len < 0:
            raise ValueError("padding_len must be >= 0")
        exts += _ext(0x0015, b"\x00" * padding_len)

    sid = os.urandom(32) if legacy_session_id is None else legacy_session_id
    body = bytearray()
    body += struct.pack(">H", 0x0303)  # legacy_version = TLS 1.2
    body += os.urandom(32)  # random
    body += bytes([len(sid)]) + sid
    body += _u16_vec(cipher_suites)
    body += b"\x01\x00"  # legacy_compression_methods: null
    body += struct.pack(">H", len(exts)) + exts

    hs_len = len(body)
    return bytes([0x01]) + struct.pack(">I", hs_len)[1:] + bytes(body)


def build_tls13_client_hello(
    server_name: str = "localhost",
    alpn: Optional[Union[bytes, Sequence[bytes]]] = ALPN_UK1,
    padding_len: Optional[int] = None,
) -> bytes:
    """Build a valid TLS 1.3 ClientHello TLS record accepted by rustls::server::Acceptor."""
    if alpn is None:
        alpn_list: Tuple[bytes, ...] = ()
    elif isinstance(alpn, (bytes, bytearray)):
        alpn_list = (bytes(alpn),)
    else:
        alpn_list = tuple(bytes(p) for p in alpn)
    hs = _build_client_hello_handshake(
        server_name=server_name,
        alpn_protocols=alpn_list,
        supported_versions=(0x0304,),
        include_key_share=True,
        padding_len=padding_len,
    )
    return split_tls_records(hs)


def build_tls12_client_hello(
    server_name: str = "localhost",
    alpn: Optional[bytes] = ALPN_UK1,
) -> bytes:
    """Build a TLS 1.2-only ClientHello (triggers rustls ProtocolVersion alert)."""
    alpn_list = (alpn,) if alpn is not None else ()
    hs = _build_client_hello_handshake(
        server_name=server_name,
        alpn_protocols=alpn_list,
        supported_versions=(0x0303,),
        cipher_suites=(0xC02F, 0xC030),
        include_key_share=False,
    )
    return split_tls_records(hs)


def build_tls_alert_record(level: int = 2, description: int = 40) -> bytes:
    """Build a raw TLS Alert record (content_type=0x15)."""
    return struct.pack(">BHHBB", 0x15, 0x0303, 2, level & 0xFF, description & 0xFF)


def build_padded_tls13_client_hello(
    total_wire_bytes: int,
    server_name: str = "localhost",
    alpn: bytes = ALPN_UK1,
) -> bytes:
    """Build a syntactically valid TLS 1.3 ClientHello whose total TLS wire bytes
    (including 5-byte TLS record headers across <=16 KiB records) equal `total_wire_bytes`.
    """
    base_hs = _build_client_hello_handshake(
        server_name=server_name,
        alpn_protocols=(alpn,),
        supported_versions=(0x0304,),
        include_key_share=True,
        padding_len=None,
    )
    min_wire = len(base_hs) + 5 * max(1, (len(base_hs) + 16383) // 16384)
    if total_wire_bytes < min_wire:
        raise ValueError(
            f"total_wire_bytes={total_wire_bytes} is smaller than minimum ClientHello ({min_wire})"
        )

    num_records = max(1, (total_wire_bytes + 16388) // 16389)
    target_hs_len = total_wire_bytes - 5 * num_records
    extra_needed = target_hs_len - len(base_hs)

    # Ensure split_tls_records emits exactly `num_records` TLS records even at
    # k*16389 + 1..5 boundaries where target_hs_len <= (num_records - 1) * 16384.
    if num_records == 1:
        max_record_payload = 16384
    else:
        max_record_payload = min(16384, (target_hs_len - 1) // (num_records - 1))

    # Extensions length field is u16 (max 65535), cipher_suites length is u16 (max 65534).
    # Keep extensions comfortably <= 65400 using padding extension, and place any overflow
    # into additional cipher suites so the ClientHello stays 100% syntactically valid.
    suites: List[int] = [0x1301, 0x1302, 0x1303]
    legacy_sid: Optional[bytes] = None
    # Measure base extensions size with padding_len=0 (adds 4 bytes)
    base_with_zero_pad = _build_client_hello_handshake(
        server_name=server_name,
        alpn_protocols=(alpn,),
        supported_versions=(0x0304,),
        cipher_suites=suites,
        include_key_share=True,
        padding_len=0,
    )
    overhead_pad_hdr = len(base_with_zero_pad) - len(base_hs)  # 4 bytes
    max_pad_for_u16 = 65200  # well within u16 extensions limit
    pad_len: Optional[int]
    if extra_needed == 0:
        pad_len = None
    elif extra_needed == 2:
        suites.append(0x0A0A)
        pad_len = None
    elif extra_needed < overhead_pad_hdr:
        # 1 or 3 byte delta: shrink 32-byte legacy_session_id by (4 - extra_needed)
        # and include an empty padding extension (+4 bytes).
        legacy_sid = os.urandom(32 - (overhead_pad_hdr - extra_needed))
        pad_len = 0
    else:
        pad_len = extra_needed - overhead_pad_hdr
        if pad_len > max_pad_for_u16:
            overflow = pad_len - max_pad_for_u16
            # Each cipher suite adds 2 bytes; round up to even
            if overflow % 2 == 1:
                overflow += 1
                pad_len = extra_needed - overhead_pad_hdr - overflow
            else:
                pad_len = max_pad_for_u16
            suites.extend([0x0A0A] * (overflow // 2))

    hs = _build_client_hello_handshake(
        server_name=server_name,
        alpn_protocols=(alpn,),
        supported_versions=(0x0304,),
        cipher_suites=suites,
        include_key_share=True,
        padding_len=pad_len,
        legacy_session_id=legacy_sid,
    )
    wire = split_tls_records(hs, max_record_payload=max_record_payload)
    if len(wire) != total_wire_bytes:
        raise AssertionError(
            f"internal padding mismatch: got {len(wire)}, expected {total_wire_bytes}"
        )
    return wire


def build_oversized_client_hello(
    total_bytes: int = 68 * 1024,
    server_name: str = "localhost",
    alpn: bytes = ALPN_UK1,
) -> bytes:
    """Build a valid multi-record TLS 1.3 ClientHello exceeding the 64 KiB cap."""
    return build_padded_tls13_client_hello(
        total_wire_bytes=total_bytes, server_name=server_name, alpn=alpn
    )


# ---------------------------------------------------------------------------
# Socket Close Semantics (macOS/Linux safe: NEVER SO_ERROR before recv)
# ---------------------------------------------------------------------------

class CloseKind(str, Enum):
    RST = "RST"
    FIN = "FIN"
    OPEN = "OPEN"
    TIMEOUT = "TIMEOUT"


@dataclass
class ProbeResult:
    received: bytes
    raw_received: bytes
    close_kind: CloseKind
    elapsed_s: float
    error: Optional[str] = None


def _connect_socket(
    host: str,
    port: int,
    source_addr: Optional[str] = None,
    timeout: float = 5.0,
) -> socket.socket:
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"cannot resolve {host}:{port}")

    last_err: Optional[OSError] = None
    for family, socktype, proto, _canon, sockaddr in infos:
        if source_addr is not None:
            src_infos = socket.getaddrinfo(
                source_addr, 0, family, socket.SOCK_STREAM
            )
            if not src_infos:
                continue
            bind_addr = src_infos[0][4]
        else:
            bind_addr = None

        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if bind_addr is not None:
                sock.bind(bind_addr)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_err = exc
            sock.close()
    if last_err is not None:
        raise last_err
    raise OSError(f"failed to connect to {host}:{port} from {source_addr}")


def read_until_close(
    sock: socket.socket,
    timeout: float = 5.0,
    decrypt_stream: Optional[ChaCha20Stream] = None,
    start_time: Optional[float] = None,
) -> ProbeResult:
    """Read from `sock` until RST, FIN, or timeout via selectors + recv().

    CRITICAL: Never calls getsockopt(SOL_SOCKET, SO_ERROR) before recv(), as doing
    so on macOS clears the pending ECONNRESET and turns RST into b"" (FIN).
    """
    t0 = time.monotonic() if start_time is None else start_time
    deadline = t0 + timeout
    raw_chunks = bytearray()
    sel = selectors.DefaultSelector()
    was_blocking = sock.getblocking()
    try:
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=CloseKind.TIMEOUT,
                    elapsed_s=time.monotonic() - t0,
                )
            events = sel.select(timeout=remaining)
            if not events:
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=CloseKind.TIMEOUT,
                    elapsed_s=time.monotonic() - t0,
                )
            try:
                chunk = sock.recv(65536)
            except BlockingIOError:
                continue
            except ConnectionResetError as exc:
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=CloseKind.RST,
                    elapsed_s=time.monotonic() - t0,
                    error=str(exc),
                )
            except OSError as exc:
                kind = (
                    CloseKind.RST
                    if exc.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE)
                    else CloseKind.FIN
                )
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=kind,
                    elapsed_s=time.monotonic() - t0,
                    error=str(exc),
                )
            if chunk == b"":
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=CloseKind.FIN,
                    elapsed_s=time.monotonic() - t0,
                )
            raw_chunks += chunk
    finally:
        sel.close()
        try:
            sock.setblocking(was_blocking)
        except OSError:
            pass


def read_first_response(
    sock: socket.socket,
    timeout: float = 3.0,
    decrypt_stream: Optional[ChaCha20Stream] = None,
) -> ProbeResult:
    """Wait for either first bytes from peer (e.g. ServerHello) or peer close."""
    t0 = time.monotonic()
    deadline = t0 + timeout
    raw_chunks = bytearray()
    sel = selectors.DefaultSelector()
    was_blocking = sock.getblocking()
    try:
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=CloseKind.TIMEOUT if not raw else CloseKind.OPEN,
                    elapsed_s=time.monotonic() - t0,
                )
            events = sel.select(timeout=remaining)
            if not events:
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=CloseKind.TIMEOUT if not raw else CloseKind.OPEN,
                    elapsed_s=time.monotonic() - t0,
                )
            try:
                chunk = sock.recv(65536)
            except BlockingIOError:
                continue
            except ConnectionResetError as exc:
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=CloseKind.RST,
                    elapsed_s=time.monotonic() - t0,
                    error=str(exc),
                )
            except OSError as exc:
                kind = (
                    CloseKind.RST
                    if exc.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE)
                    else CloseKind.FIN
                )
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=kind,
                    elapsed_s=time.monotonic() - t0,
                    error=str(exc),
                )
            if chunk == b"":
                raw = bytes(raw_chunks)
                dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                return ProbeResult(
                    received=dec,
                    raw_received=raw,
                    close_kind=CloseKind.FIN,
                    elapsed_s=time.monotonic() - t0,
                )
            raw_chunks += chunk
            # Drain any immediately available buffered data before returning OPEN
            while True:
                try:
                    more = sock.recv(65536)
                except BlockingIOError:
                    raw = bytes(raw_chunks)
                    dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                    return ProbeResult(
                        received=dec,
                        raw_received=raw,
                        close_kind=CloseKind.OPEN,
                        elapsed_s=time.monotonic() - t0,
                    )
                except ConnectionResetError as exc:
                    raw = bytes(raw_chunks)
                    dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                    return ProbeResult(
                        received=dec,
                        raw_received=raw,
                        close_kind=CloseKind.RST,
                        elapsed_s=time.monotonic() - t0,
                        error=str(exc),
                    )
                except OSError as exc:
                    kind = (
                        CloseKind.RST
                        if exc.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE)
                        else CloseKind.FIN
                    )
                    raw = bytes(raw_chunks)
                    dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                    return ProbeResult(
                        received=dec,
                        raw_received=raw,
                        close_kind=kind,
                        elapsed_s=time.monotonic() - t0,
                        error=str(exc),
                    )
                if more == b"":
                    raw = bytes(raw_chunks)
                    dec = decrypt_stream.apply(raw) if decrypt_stream else raw
                    return ProbeResult(
                        received=dec,
                        raw_received=raw,
                        close_kind=CloseKind.FIN,
                        elapsed_s=time.monotonic() - t0,
                    )
                raw_chunks += more
    finally:
        sel.close()
        try:
            sock.setblocking(was_blocking)
        except OSError:
            pass


def check_socket_closed(sock: socket.socket, timeout: float = 0.25) -> CloseKind:
    """Check whether a connected socket is closed (RST/FIN) or still OPEN."""
    sel = selectors.DefaultSelector()
    was_blocking = sock.getblocking()
    try:
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ)
        events = sel.select(timeout=timeout)
        if not events:
            return CloseKind.OPEN
        try:
            data = sock.recv(4096)
        except BlockingIOError:
            return CloseKind.OPEN
        except ConnectionResetError:
            return CloseKind.RST
        except OSError as exc:
            if exc.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE):
                return CloseKind.RST
            return CloseKind.FIN
        return CloseKind.FIN if data == b"" else CloseKind.OPEN
    finally:
        sel.close()
        try:
            sock.setblocking(was_blocking)
        except OSError:
            pass


class MaskedTcpProbe:
    """Wire-level TCP probe helper supporting unmasked and masked UK connections."""

    @staticmethod
    def open_socket(
        host: str,
        port: int,
        source_addr: Optional[str] = None,
        timeout: float = 5.0,
    ) -> socket.socket:
        return _connect_socket(host, port, source_addr=source_addr, timeout=timeout)

    @staticmethod
    def send_and_probe(
        host: str,
        port: int,
        payload: bytes,
        decrypt_s2c: Optional[ChaCha20Stream] = None,
        source_addr: Optional[str] = None,
        timeout: float = 5.0,
        fragment_sizes: Optional[Sequence[int]] = None,
        fragment_delay_s: float = 0.0,
        shutdown_wr: bool = False,
        wait_for_close: bool = True,
    ) -> ProbeResult:
        t0 = time.monotonic()
        sock = _connect_socket(host, port, source_addr=source_addr, timeout=timeout)
        try:
            if payload:
                if fragment_sizes:
                    off = 0
                    idx = 0
                    while off < len(payload):
                        sz = fragment_sizes[idx % len(fragment_sizes)]
                        sock.sendall(payload[off : off + sz])
                        off += sz
                        idx += 1
                        if fragment_delay_s > 0 and off < len(payload):
                            time.sleep(fragment_delay_s)
                else:
                    sock.sendall(payload)
            if shutdown_wr:
                sock.shutdown(socket.SHUT_WR)
            if wait_for_close:
                return read_until_close(
                    sock, timeout=timeout, decrypt_stream=decrypt_s2c, start_time=t0
                )
            return read_first_response(
                sock, timeout=timeout, decrypt_stream=decrypt_s2c
            )
        finally:
            sock.close()

    @classmethod
    def probe_masked(
        cls,
        host: str,
        port: int,
        keys: MaskKeys,
        identity: int,
        counter: int,
        plaintext_after_prelude: bytes,
        policy: str = "fade",
        nonce: Optional[bytes] = None,
        high_bits_override: Optional[Union[bytes, int]] = None,
        allow_zero_counter: bool = False,
        source_addr: Optional[str] = None,
        timeout: float = 5.0,
        fragment_sizes: Optional[Sequence[int]] = None,
        fragment_delay_s: float = 0.0,
        shutdown_wr: bool = False,
        wait_for_close: bool = True,
    ) -> ProbeResult:
        prelude_wire, used_nonce = encode_prelude(
            keys=keys,
            identity=identity,
            counter=counter,
            policy=policy,
            nonce=nonce,
            high_bits_override=high_bits_override,
            allow_zero_counter=allow_zero_counter,
        )
        c2s = ChaCha20Stream(keys.tcp_c2s, used_nonce)
        s2c = ChaCha20Stream(keys.tcp_s2c, used_nonce)
        wire = prelude_wire + c2s.apply(plaintext_after_prelude)
        return cls.send_and_probe(
            host=host,
            port=port,
            payload=wire,
            decrypt_s2c=s2c,
            source_addr=source_addr,
            timeout=timeout,
            fragment_sizes=fragment_sizes,
            fragment_delay_s=fragment_delay_s,
            shutdown_wr=shutdown_wr,
            wait_for_close=wait_for_close,
        )


# ---------------------------------------------------------------------------
# Masked QUIC UDP Probe Socket
# ---------------------------------------------------------------------------

def build_quic_initial_probe(
    version: int = QUIC_V1,
    size: int = 1200,
    dcid: Optional[bytes] = None,
    scid: Optional[bytes] = None,
) -> bytes:
    """Build a syntactically valid QUIC Long Header Initial packet."""
    dcid_b = os.urandom(8) if dcid is None else dcid
    scid_b = os.urandom(8) if scid is None else scid
    header = bytearray()
    header.append(0xC0 | 0x03)  # Long header, Initial (0x0), packet len=4
    header += struct.pack(">I", version)
    header.append(len(dcid_b))
    header += dcid_b
    header.append(len(scid_b))
    header += scid_b
    header.append(0x00)  # token_len = 0
    payload_len = max(16, size - len(header) - 2)
    # 2-byte QUIC varint for payload length (0x4000 | len)
    header += struct.pack(">H", 0x4000 | (payload_len & 0x3FFF))
    pkt = bytes(header) + os.urandom(payload_len)
    return pkt[:size] if len(pkt) >= size else pkt + b"\x00" * (size - len(pkt))


class QuicProbeSocket:
    """UDP probe socket for masked/unmasked QUIC server ports."""

    def __init__(
        self,
        host: str,
        port: int,
        source_addr: Optional[str] = None,
    ) -> None:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        if not infos:
            raise OSError(f"cannot resolve UDP {host}:{port}")
        family, socktype, proto, _canon, sockaddr = infos[0]
        self._sock = socket.socket(family, socktype, proto)
        self._target = sockaddr
        if source_addr is not None:
            src_infos = socket.getaddrinfo(
                source_addr, 0, family, socket.SOCK_DGRAM
            )
            self._sock.bind(src_infos[0][4])
        else:
            bind_host = "::" if family == socket.AF_INET6 else "0.0.0.0"
            self._sock.bind((bind_host, 0))
        self._sock.setblocking(False)

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> "QuicProbeSocket":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def send_raw(self, data: bytes) -> int:
        return self._sock.sendto(data, self._target)

    def send_masked(
        self,
        keys: MaskKeys,
        payload: bytes,
        nonce: Optional[bytes] = None,
    ) -> int:
        used_nonce = os.urandom(NONCE_LEN) if nonce is None else bytes(nonce)
        if len(used_nonce) != NONCE_LEN:
            raise ValueError(f"nonce must be {NONCE_LEN} bytes")
        enc = ChaCha20Stream(keys.udp_c2s, used_nonce).apply(payload)
        return self._sock.sendto(used_nonce + enc, self._target)

    def recv_packets(
        self,
        timeout: float = 0.5,
        max_packets: int = 32,
    ) -> List[bytes]:
        packets: List[bytes] = []
        deadline = time.monotonic() + timeout
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._sock, selectors.EVENT_READ)
            while len(packets) < max_packets:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                events = sel.select(timeout=remaining)
                if not events:
                    break
                while len(packets) < max_packets:
                    try:
                        pkt, _addr = self._sock.recvfrom(65535)
                        packets.append(pkt)
                    except BlockingIOError:
                        break
                    except OSError:
                        break
        finally:
            sel.close()
        return packets


class UdpObserverProxy:
    """Transparent local UDP proxy recording every client<->server datagram."""

    def __init__(self, upstream_host: str, upstream_port: int) -> None:
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._family = socket.AF_INET6 if ":" in upstream_host else socket.AF_INET
        bind_host = "::1" if self._family == socket.AF_INET6 else "127.0.0.1"
        self._cli_sock = socket.socket(self._family, socket.SOCK_DGRAM)
        self._cli_sock.bind((bind_host, 0))
        self._cli_sock.setblocking(False)
        self.listen_host = bind_host
        self.port = int(self._cli_sock.getsockname()[1])

        self._up_sock = socket.socket(self._family, socket.SOCK_DGRAM)
        self._up_sock.bind((bind_host, 0))
        self._up_sock.setblocking(False)
        infos = socket.getaddrinfo(
            upstream_host, upstream_port, self._family, socket.SOCK_DGRAM
        )
        self._upstream_addr = infos[0][4]

        self.c2s: List[bytes] = []
        self.s2c: List[bytes] = []
        self._cli_addr: Optional[Tuple[object, ...]] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="uk-udp-observer", daemon=True
        )

    def start(self) -> "UdpObserverProxy":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3.0)
        for s in (self._cli_sock, self._up_sock):
            try:
                s.close()
            except OSError:
                pass

    def __enter__(self) -> "UdpObserverProxy":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.stop()

    def snapshot(self) -> Tuple[List[bytes], List[bytes]]:
        with self._lock:
            return list(self.c2s), list(self.s2c)

    def _run(self) -> None:
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._cli_sock, selectors.EVENT_READ, data="c2s")
            sel.register(self._up_sock, selectors.EVENT_READ, data="s2c")
            while not self._stop.is_set():
                try:
                    events = sel.select(timeout=0.05)
                except (OSError, ValueError):
                    break
                for key, _ in events:
                    if key.data == "c2s":
                        while True:
                            try:
                                data, addr = self._cli_sock.recvfrom(65535)
                            except BlockingIOError:
                                break
                            except OSError:
                                return
                            with self._lock:
                                self._cli_addr = addr
                                self.c2s.append(data)
                            try:
                                self._up_sock.sendto(data, self._upstream_addr)
                            except OSError:
                                if self._stop.is_set():
                                    return
                    else:
                        while True:
                            try:
                                data, _ = self._up_sock.recvfrom(65535)
                            except BlockingIOError:
                                break
                            except OSError:
                                return
                            with self._lock:
                                self.s2c.append(data)
                                dst = self._cli_addr
                            if dst is not None:
                                try:
                                    self._cli_sock.sendto(data, dst)
                                except OSError:
                                    if self._stop.is_set():
                                        return
        finally:
            sel.close()

    def non_retry_s2c_packets(self, keys: MaskKeys) -> List[bytes]:
        """Decrypt server->client packets with `udp_s2c` and return any non-Retry packets."""
        out: List[bytes] = []
        with self._lock:
            pkts = list(self.s2c)
        for pkt in pkts:
            if len(pkt) <= 12:
                out.append(pkt)
                continue
            dec = ChaCha20Stream(keys.udp_s2c, pkt[:12]).apply(pkt[12:])
            is_v1_retry = (
                len(dec) >= 7
                and (dec[0] & 0xF0) == 0xF0
                and dec[1:5] == b"\x00\x00\x00\x01"
            )
            if not is_v1_retry:
                out.append(dec)
        return out


# ---------------------------------------------------------------------------
# Pure-Stdlib SOCKS5 TCP & UDP Client
# ---------------------------------------------------------------------------

class Socks5Error(RuntimeError):
    """Raised when a SOCKS5 handshake or command returns a non-zero reply code."""

    def __init__(self, reply_code: int, message: str = "") -> None:
        self.reply_code = reply_code
        super().__init__(message or f"SOCKS5 error reply code 0x{reply_code:02x}")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"unexpected EOF reading {n} bytes (got {len(buf)})")
        buf += chunk
    return bytes(buf)


def _encode_socks5_addr(host: str, port: int) -> bytes:
    try:
        ipv4 = socket.inet_pton(socket.AF_INET, host)
        return b"\x01" + ipv4 + struct.pack(">H", port)
    except OSError:
        pass
    try:
        ipv6 = socket.inet_pton(socket.AF_INET6, host.split("%", 1)[0])
        return b"\x04" + ipv6 + struct.pack(">H", port)
    except OSError:
        pass
    host_b = host.encode("utf-8")
    return b"\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", port)


def _decode_socks5_addr_from_socket(sock: socket.socket) -> Tuple[str, int]:
    hdr = _recv_exact(sock, 4)
    if hdr[0] != 0x05:
        raise Socks5Error(hdr[1], f"unexpected SOCKS5 version {hdr[0]}")
    rep = hdr[1]
    atyp = hdr[3]
    if atyp == 0x01:
        addr = socket.inet_ntop(socket.AF_INET, _recv_exact(sock, 4))
    elif atyp == 0x04:
        addr = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
    elif atyp == 0x03:
        ln = _recv_exact(sock, 1)[0]
        addr = _recv_exact(sock, ln).decode("utf-8", errors="replace")
    else:
        raise Socks5Error(rep, f"unsupported ATYP 0x{atyp:02x}")
    port = struct.unpack(">H", _recv_exact(sock, 2))[0]
    if rep != 0x00:
        raise Socks5Error(rep, f"SOCKS5 command failed with reply 0x{rep:02x}")
    return addr, port


class Socks5Client:
    """Minimal pure-stdlib SOCKS5 TCP CONNECT and UDP ASSOCIATE client."""

    @staticmethod
    def _greeting(sock: socket.socket) -> None:
        sock.sendall(b"\x05\x01\x00")
        resp = _recv_exact(sock, 2)
        if resp != b"\x05\x00":
            raise Socks5Error(resp[1] if len(resp) > 1 else 0xFF, f"auth failed: {resp!r}")

    @classmethod
    def socks5_connect(
        cls,
        socks_host: str,
        socks_port: int,
        target_host: str,
        target_port: int,
        timeout: float = 10.0,
    ) -> socket.socket:
        sock = _connect_socket(socks_host, socks_port, timeout=timeout)
        try:
            cls._greeting(sock)
            req = b"\x05\x01\x00" + _encode_socks5_addr(target_host, target_port)
            sock.sendall(req)
            _decode_socks5_addr_from_socket(sock)
            return sock
        except Exception:
            sock.close()
            raise

    @classmethod
    def socks5_echo(
        cls,
        socks_host: str,
        socks_port: int,
        target_host: str,
        target_port: int,
        data: bytes,
        timeout: float = 15.0,
        shutdown_wr_after_send: bool = True,
    ) -> bytes:
        sock = cls.socks5_connect(
            socks_host, socks_port, target_host, target_port, timeout=timeout
        )
        try:
            sock.settimeout(timeout)
            sock.sendall(data)
            if shutdown_wr_after_send:
                sock.shutdown(socket.SHUT_WR)
                out = bytearray()
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    out += chunk
                return bytes(out)
            else:
                return _recv_exact(sock, len(data))
        finally:
            sock.close()

    @classmethod
    def _http_request(
        cls,
        method: str,
        socks_host: str,
        socks_port: int,
        target_host: str,
        target_port: int,
        path: str = "/",
        body: bytes = b"",
        timeout: float = 15.0,
    ) -> Tuple[int, Dict[str, str], bytes]:
        sock = cls.socks5_connect(
            socks_host, socks_port, target_host, target_port, timeout=timeout
        )
        try:
            sock.settimeout(timeout)
            host_hdr = (
                f"[{target_host}]:{target_port}"
                if ":" in target_host
                else f"{target_host}:{target_port}"
            )
            headers = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host_hdr}",
                "Connection: close",
            ]
            if body or method == "POST":
                headers.append(f"Content-Length: {len(body)}")
                headers.append("Content-Type: application/octet-stream")
            raw_req = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
            sock.sendall(raw_req)
            raw_resp = bytearray()
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw_resp += chunk
            sep = raw_resp.find(b"\r\n\r\n")
            if sep < 0:
                raise ValueError(f"malformed HTTP response: {bytes(raw_resp[:128])!r}")
            head_lines = raw_resp[:sep].decode("iso-8859-1").split("\r\n")
            status = int(head_lines[0].split(" ", 2)[1])
            resp_headers: Dict[str, str] = {}
            for line in head_lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()
            resp_body = bytes(raw_resp[sep + 4 :])
            return status, resp_headers, resp_body
        finally:
            sock.close()

    @classmethod
    def socks5_http_get(
        cls,
        socks_host: str,
        socks_port: int,
        target_host: str,
        target_port: int,
        path: str = "/",
        timeout: float = 15.0,
    ) -> Tuple[int, Dict[str, str], bytes]:
        return cls._http_request(
            "GET", socks_host, socks_port, target_host, target_port, path=path, timeout=timeout
        )

    @classmethod
    def socks5_http_post(
        cls,
        socks_host: str,
        socks_port: int,
        target_host: str,
        target_port: int,
        path: str = "/echo",
        body: bytes = b"",
        timeout: float = 15.0,
    ) -> Tuple[int, Dict[str, str], bytes]:
        return cls._http_request(
            "POST",
            socks_host,
            socks_port,
            target_host,
            target_port,
            path=path,
            body=body,
            timeout=timeout,
        )

    @classmethod
    def socks5_udp_associate(
        cls,
        socks_host: str,
        socks_port: int,
        timeout: float = 10.0,
    ) -> Tuple[socket.socket, socket.socket, Tuple[str, int]]:
        ctrl = _connect_socket(socks_host, socks_port, timeout=timeout)
        try:
            cls._greeting(ctrl)
            ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            relay_ip, relay_port = _decode_socks5_addr_from_socket(ctrl)
            if relay_ip in ("0.0.0.0", "::"):
                relay_ip = socks_host
            family = socket.AF_INET6 if ":" in relay_ip else socket.AF_INET
            udp_sock = socket.socket(family, socket.SOCK_DGRAM)
            udp_sock.settimeout(timeout)
            udp_sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
            return ctrl, udp_sock, (relay_ip, relay_port)
        except Exception:
            ctrl.close()
            raise

    @classmethod
    def socks5_udp_exchange(
        cls,
        socks_host: str,
        socks_port: int,
        target_host: str,
        target_port: int,
        payloads: Sequence[bytes],
        timeout: float = 10.0,
    ) -> List[bytes]:
        ctrl, udp_sock, relay = cls.socks5_udp_associate(
            socks_host, socks_port, timeout=timeout
        )
        results: List[bytes] = []
        try:
            addr_hdr = _encode_socks5_addr(target_host, target_port)
            for payload in payloads:
                pkt = b"\x00\x00\x00" + addr_hdr + payload
                udp_sock.sendto(pkt, relay)
                resp, _from = udp_sock.recvfrom(65535)
                if len(resp) < 4 or resp[:3] != b"\x00\x00\x00":
                    raise ValueError(f"invalid SOCKS5 UDP response header: {resp[:8]!r}")
                atyp = resp[3]
                if atyp == 0x01:
                    hdr_len = 10
                elif atyp == 0x04:
                    hdr_len = 22
                elif atyp == 0x03:
                    hdr_len = 4 + 1 + resp[4] + 2
                else:
                    raise ValueError(f"unsupported SOCKS5 UDP ATYP 0x{atyp:02x}")
                results.append(resp[hdr_len:])
            return results
        finally:
            udp_sock.close()
            ctrl.close()


# ---------------------------------------------------------------------------
# TransparentFirstSegmentProxy & StallProxy
# ---------------------------------------------------------------------------

class TransparentFirstSegmentProxy:
    """TCP proxy that records the exact byte length & content of the client's
    first TCP segment (`recv(65536)`) before forwarding with `TCP_NODELAY=1`.

    Supports optional `split_chunk_size` to fragment client->server bytes.
    """

    def __init__(
        self,
        upstream_host: str,
        upstream_port: int,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        split_chunk_size: Optional[int] = None,
    ) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.split_chunk_size = split_chunk_size

        family = socket.AF_INET6 if ":" in listen_host else socket.AF_INET
        self._listener = socket.socket(family, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((listen_host, listen_port))
        self._listener.listen(64)
        self._listener.setblocking(False)
        self.listen_host = listen_host
        self.listen_port = self._listener.getsockname()[1]

        self._stop_event = threading.Event()
        self._first_event = threading.Event()
        self._lock = threading.Lock()
        self.first_segments: List[bytes] = []
        self._threads: List[threading.Thread] = []
        self._accept_thread: Optional[threading.Thread] = None

    @property
    def first_segment_bytes(self) -> Optional[bytes]:
        with self._lock:
            return self.first_segments[0] if self.first_segments else None

    @property
    def first_segment_len(self) -> Optional[int]:
        with self._lock:
            return len(self.first_segments[0]) if self.first_segments else None

    def start(self) -> "TransparentFirstSegmentProxy":
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="uk-first-seg-proxy", daemon=True
        )
        self._accept_thread.start()
        return self

    def stop(self) -> None:
        self._stop_event.set()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=3.0)
        try:
            self._listener.close()
        except OSError:
            pass
        for t in list(self._threads):
            t.join(timeout=3.0)

    def __enter__(self) -> "TransparentFirstSegmentProxy":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.stop()

    def wait_for_first_segment(self, timeout: float = 10.0) -> bytes:
        if not self._first_event.wait(timeout=timeout):
            raise TimeoutError("timed out waiting for first client segment")
        seg = self.first_segment_bytes
        assert seg is not None
        return seg

    def _accept_loop(self) -> None:
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._listener, selectors.EVENT_READ)
            while not self._stop_event.is_set():
                try:
                    events = sel.select(timeout=0.05)
                except (OSError, ValueError):
                    break
                if not events:
                    continue
                try:
                    cli, _addr = self._listener.accept()
                except OSError:
                    break
                t = threading.Thread(
                    target=self._relay_conn, args=(cli,), daemon=True
                )
                self._threads.append(t)
                t.start()
        finally:
            sel.close()

    def _send_client_data(self, dst: socket.socket, data: bytes) -> None:
        if self.split_chunk_size is None or self.split_chunk_size <= 0:
            dst.sendall(data)
            return
        for off in range(0, len(data), self.split_chunk_size):
            dst.sendall(data[off : off + self.split_chunk_size])

    def _relay_conn(self, cli: socket.socket) -> None:
        up: Optional[socket.socket] = None
        sel = selectors.DefaultSelector()
        try:
            cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            up = _connect_socket(self.upstream_host, self.upstream_port, timeout=5.0)
            up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            cli.setblocking(False)
            up.setblocking(False)
            sel.register(cli, selectors.EVENT_READ, data="c2s")
            sel.register(up, selectors.EVENT_READ, data="s2c")
            recorded_first = False

            while not self._stop_event.is_set():
                if not sel.get_map():
                    break
                events = sel.select(timeout=0.05)
                for key, _mask in events:
                    sock = key.fileobj
                    assert isinstance(sock, socket.socket)
                    if key.data == "c2s":
                        try:
                            data = sock.recv(65536)
                        except BlockingIOError:
                            continue
                        except OSError:
                            data = b""
                        if not data:
                            sel.unregister(cli)
                            try:
                                up.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                            continue
                        if not recorded_first:
                            recorded_first = True
                            with self._lock:
                                self.first_segments.append(data)
                            self._first_event.set()
                        up.setblocking(True)
                        try:
                            self._send_client_data(up, data)
                        finally:
                            up.setblocking(False)
                    else:
                        try:
                            data = sock.recv(65536)
                        except BlockingIOError:
                            continue
                        except OSError:
                            data = b""
                        if not data:
                            sel.unregister(up)
                            try:
                                cli.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                            continue
                        cli.setblocking(True)
                        try:
                            cli.sendall(data)
                        finally:
                            cli.setblocking(False)
        except OSError:
            pass
        finally:
            sel.close()
            try:
                cli.close()
            except OSError:
                pass
            if up is not None:
                try:
                    up.close()
                except OSError:
                    pass


@dataclass
class StallSessionRecord:
    index: int
    accepted_at: float
    upstream_connected_at: float
    phase1_bytes: int = 0
    phase1_forwarded_at: Optional[float] = None
    server_first_reply_at: Optional[float] = None
    phase2_received_at: Optional[float] = None
    server_closed_at: Optional[float] = None
    server_close_kind: CloseKind = CloseKind.OPEN
    elapsed_s: Optional[float] = None
    done_event: threading.Event = field(default_factory=threading.Event, repr=False)


class StallProxy:
    """Timing-fault proxy for R4 shared-deadline tests.

    - Phase 1: buffers initial client write (`prelude+ClientHello`), delays
      forwarding to upstream by `phase1_delay_s`.
    - Server reply (`ServerHello+...AuthChallenge`): forwarded immediately to client.
    - Phase 2: once server has replied, subsequent client bytes (`Finished+AuthResponse`)
      are held for `phase2_delay_s` (or indefinitely if `hold_phase2=True` / `phase2_delay_s=None`).
    - Detects exact `server_close_kind` (`RST` vs `FIN`) directly from `upstream.recv()`
      (never calling `SO_ERROR` first) and records `elapsed_s` from `upstream_connected_at`.
    """

    def __init__(
        self,
        upstream_host: str,
        upstream_port: int,
        phase1_delay_s: float = 0.0,
        phase2_delay_s: Optional[float] = None,
        hold_phase2: bool = True,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
    ) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.phase1_delay_s = phase1_delay_s
        self.phase2_delay_s = phase2_delay_s
        self.hold_phase2 = hold_phase2

        family = socket.AF_INET6 if ":" in listen_host else socket.AF_INET
        self._listener = socket.socket(family, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((listen_host, listen_port))
        self._listener.listen(64)
        self._listener.setblocking(False)
        self.listen_host = listen_host
        self.listen_port = self._listener.getsockname()[1]

        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self.sessions: List[StallSessionRecord] = []
        self._session_added = threading.Event()
        self._threads: List[threading.Thread] = []
        self._accept_thread: Optional[threading.Thread] = None

    def start(self) -> "StallProxy":
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="uk-stall-proxy", daemon=True
        )
        self._accept_thread.start()
        return self

    def stop(self) -> None:
        self._stop_event.set()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=3.0)
        try:
            self._listener.close()
        except OSError:
            pass
        for t in list(self._threads):
            t.join(timeout=3.0)

    def __enter__(self) -> "StallProxy":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.stop()

    def wait_for_session_close(
        self, index: int = 0, timeout: float = 15.0
    ) -> StallSessionRecord:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if len(self.sessions) > index:
                    rec = self.sessions[index]
                    break
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"timed out waiting for stall session #{index}")
            self._session_added.wait(timeout=min(0.05, rem))
        rem = deadline - time.monotonic()
        if rem <= 0 or not rec.done_event.wait(timeout=rem):
            raise TimeoutError(f"timed out waiting for upstream close on session #{index}")
        return rec

    def _accept_loop(self) -> None:
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._listener, selectors.EVENT_READ)
            while not self._stop_event.is_set():
                try:
                    events = sel.select(timeout=0.05)
                except (OSError, ValueError):
                    break
                if not events:
                    continue
                try:
                    cli, _addr = self._listener.accept()
                except OSError:
                    break
                t = threading.Thread(
                    target=self._handle_conn, args=(cli,), daemon=True
                )
                self._threads.append(t)
                t.start()
        finally:
            sel.close()

    def _handle_conn(self, cli: socket.socket) -> None:
        accepted_at = time.monotonic()
        up: Optional[socket.socket] = None
        sel = selectors.DefaultSelector()
        rec: Optional[StallSessionRecord] = None
        try:
            cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            up = _connect_socket(self.upstream_host, self.upstream_port, timeout=5.0)
            up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            up_conn_at = time.monotonic()
            with self._lock:
                idx = len(self.sessions)
                rec = StallSessionRecord(
                    index=idx,
                    accepted_at=accepted_at,
                    upstream_connected_at=up_conn_at,
                )
                self.sessions.append(rec)
                self._session_added.set()

            cli.setblocking(False)
            up.setblocking(False)
            sel.register(cli, selectors.EVENT_READ, data="c2s")
            sel.register(up, selectors.EVENT_READ, data="s2c")

            phase1_buf = bytearray()
            phase1_release_at: Optional[float] = None
            phase1_forwarded = False
            server_replied = False

            phase2_buf = bytearray()
            phase2_release_at: Optional[float] = None
            phase2_holding = False

            while not self._stop_event.is_set():
                now = time.monotonic()
                if (
                    not phase1_forwarded
                    and phase1_release_at is not None
                    and now >= phase1_release_at
                ):
                    if phase1_buf:
                        up.setblocking(True)
                        try:
                            up.sendall(bytes(phase1_buf))
                        finally:
                            up.setblocking(False)
                        phase1_buf.clear()
                    phase1_forwarded = True
                    rec.phase1_forwarded_at = time.monotonic()

                if (
                    phase2_holding
                    and not self.hold_phase2
                    and phase2_release_at is not None
                    and now >= phase2_release_at
                ):
                    if phase2_buf:
                        up.setblocking(True)
                        try:
                            up.sendall(bytes(phase2_buf))
                        finally:
                            up.setblocking(False)
                        phase2_buf.clear()
                    phase2_holding = False

                next_wait = 0.05
                if not phase1_forwarded and phase1_release_at is not None:
                    next_wait = min(next_wait, max(0.005, phase1_release_at - now))
                if (
                    phase2_holding
                    and not self.hold_phase2
                    and phase2_release_at is not None
                ):
                    next_wait = min(next_wait, max(0.005, phase2_release_at - now))

                if not sel.get_map():
                    break
                events = sel.select(timeout=next_wait)
                for key, _mask in events:
                    if key.data == "c2s":
                        try:
                            data = cli.recv(65536)
                        except BlockingIOError:
                            continue
                        except OSError:
                            data = b""
                        if not data:
                            try:
                                sel.unregister(cli)
                            except KeyError:
                                pass
                            continue
                        if not phase1_forwarded:
                            phase1_buf += data
                            rec.phase1_bytes += len(data)
                            if phase1_release_at is None:
                                phase1_release_at = time.monotonic() + self.phase1_delay_s
                        elif server_replied and (self.hold_phase2 or self.phase2_delay_s is not None):
                            phase2_buf += data
                            if rec.phase2_received_at is None:
                                rec.phase2_received_at = time.monotonic()
                            if not phase2_holding:
                                phase2_holding = True
                                if self.phase2_delay_s is not None and not self.hold_phase2:
                                    phase2_release_at = time.monotonic() + self.phase2_delay_s
                        else:
                            up.setblocking(True)
                            try:
                                up.sendall(data)
                            finally:
                                up.setblocking(False)
                    else:
                        try:
                            data = up.recv(65536)
                        except BlockingIOError:
                            continue
                        except ConnectionResetError:
                            rec.server_closed_at = time.monotonic()
                            rec.server_close_kind = CloseKind.RST
                            rec.elapsed_s = rec.server_closed_at - rec.upstream_connected_at
                            return
                        except OSError as exc:
                            rec.server_closed_at = time.monotonic()
                            rec.server_close_kind = (
                                CloseKind.RST
                                if exc.errno
                                in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE)
                                else CloseKind.FIN
                            )
                            rec.elapsed_s = rec.server_closed_at - rec.upstream_connected_at
                            return
                        if data == b"":
                            rec.server_closed_at = time.monotonic()
                            rec.server_close_kind = CloseKind.FIN
                            rec.elapsed_s = rec.server_closed_at - rec.upstream_connected_at
                            return
                        server_replied = True
                        if rec.server_first_reply_at is None:
                            rec.server_first_reply_at = time.monotonic()
                        cli.setblocking(True)
                        try:
                            cli.sendall(data)
                        finally:
                            cli.setblocking(False)
        except OSError:
            if rec is not None and rec.server_closed_at is None:
                rec.server_closed_at = time.monotonic()
                rec.server_close_kind = CloseKind.RST
                rec.elapsed_s = rec.server_closed_at - rec.upstream_connected_at
        finally:
            if rec is not None:
                rec.done_event.set()
            sel.close()
            try:
                cli.close()
            except OSError:
                pass
            if up is not None:
                try:
                    up.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Self-Test (RFC 8439 §2.3.2 vector & prelude roundtrip)
# ---------------------------------------------------------------------------

def self_test() -> None:
    """Verify RFC 8439 §2.3.2 ChaCha20 vector, MaskKeys KDF, and prelude roundtrip."""
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    blk = chacha20_block(key, 1, nonce)
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert blk == expected, f"RFC 8439 §2.3.2 mismatch: {blk.hex()}"

    # Verify ChaCha20Stream starts at block counter 0 and handles unaligned chunks
    s1 = ChaCha20Stream(key, nonce)
    s2 = ChaCha20Stream(key, nonce)
    msg = os.urandom(200)
    assert s1.apply(msg) == (s2.apply(msg[:17]) + s2.apply(msg[17:100]) + s2.apply(msg[100:]))

    # Verify prelude roundtrip across all policies and edge high-bits
    mk = derive_mask_keys("k1", "a-very-long-secret-at-least-32-bytes-long")
    for pol in ("fade", "full8", "low7"):
        wire, n = encode_prelude(mk, identity=0x123456789ABCDEF0, counter=42, policy=pol)
        assert len(wire) == WIRE_PRELUDE_LEN
        dec_k, dec_id, dec_ctr, dec_n = decode_prelude([mk], wire)
        assert dec_k == mk and dec_id == 0x123456789ABCDEF0 and dec_ctr == 42 and dec_n == n

    for hb in (0x00, 0x80):
        wire, _ = encode_prelude(mk, identity=7, counter=MAX_COUNTER, high_bits_override=hb)
        tail = wire[PREFIX_LEN:PRELUDE_LEN]
        assert all((b & 0x80) == hb for b in tail)
        _, dec_id, dec_ctr, _ = decode_prelude(mk, wire)
        assert dec_id == 7 and dec_ctr == MAX_COUNTER
