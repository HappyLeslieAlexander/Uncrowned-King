//! ChaCha20 masking for QUIC datagrams.
//!
//! A [`MaskedUdpSocket`] wraps quinn's `AsyncUdpSocket` so every QUIC segment
//! on the wire becomes `nonce(12) ‖ ChaCha20(segment)` under the
//! per-credential UDP direction keys: long-header Initials (whose ClientHello
//! an observer could otherwise decrypt with publicly derivable keys, RFC 9001
//! §5.2), short-header packets, and even Retry and Version Negotiation packets
//! all become random bytes. This is masking only; QUIC's own AEAD remains the
//! cryptographic boundary.
//!
//! # Server-side ingress filter
//!
//! After unmasking, a server-role socket checks every segment: short headers
//! pass; long headers must carry a supported QUIC version. Anything else —
//! including Version Negotiation–style version 0 — is silently dropped, so an
//! unauthenticated prober never even triggers a Version Negotiation response.
//!
//! # Multi-credential note
//!
//! Unlike the TCP prelude, a UDP datagram carries no authentication of its
//! own, so the server cannot try each credential's key per packet. The
//! endpoint is masked under exactly *one* designated credential's keys
//! (see the server's `[masking] quic_key_id`); connections still authenticate
//! individually afterwards. Endpoint masking keys are therefore pinned at
//! startup: rotating the designated credential requires a restart.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use chacha20::{ChaCha20, Key, KeyIvInit, Nonce, cipher::StreamCipher};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{MaskKeys, NONCE_LEN};

/// Bytes of per-segment masking overhead added on the wire.
pub const UDP_SEGMENT_OVERHEAD: usize = NONCE_LEN;

/// Which side of the carrier this socket masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRole {
    /// Client: sends with the c2s key, receives with s2c.
    Client,
    /// Server: sends with the s2c key, receives with c2s, and filters
    /// unsupported QUIC versions after unmasking.
    Server,
}

/// Refills its keystream buffer from a ChaCha20 instance seeded with fresh
/// random bytes, and reseeds long before the keystream length cap.
struct NonceGenerator {
    cipher: ChaCha20,
    buffer: Zeroizing<[u8; NONCE_BUFFER_LEN]>,
    position: usize,
    generated: u64,
}

/// Keystream bytes buffered per refill. 4096 is enough for 341 datagrams.
const NONCE_BUFFER_LEN: usize = 4096;
/// Conservative reseed bound, far below ChaCha20's 2^38-byte stream cap.
const NONCE_RESEED_BYTES: u64 = 1 << 32;

impl NonceGenerator {
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0_u8; 32]);
        rng.fill_bytes(&mut *seed);
        Self {
            cipher: ChaCha20::new(&Key::from(*seed), &Nonce::from([0_u8; NONCE_LEN])),
            buffer: Zeroizing::new([0_u8; NONCE_BUFFER_LEN]),
            position: NONCE_BUFFER_LEN,
            generated: 0,
        }
    }

    fn next(&mut self) -> [u8; NONCE_LEN] {
        if self.position + NONCE_LEN > NONCE_BUFFER_LEN {
            if self.generated >= NONCE_RESEED_BYTES {
                let mut seed = Zeroizing::new([0_u8; 32]);
                rand::rngs::OsRng.fill_bytes(&mut *seed);
                self.cipher = ChaCha20::new(&Key::from(*seed), &Nonce::from([0_u8; NONCE_LEN]));
                self.generated = 0;
            }
            self.cipher
                .try_apply_keystream(&mut self.buffer[..])
                .expect("nonce keystream is far below the ChaCha20 cap");
            self.position = 0;
            self.generated += NONCE_BUFFER_LEN as u64;
        }
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&self.buffer[self.position..self.position + NONCE_LEN]);
        self.position += NONCE_LEN;
        nonce
    }
}

struct UdpSendState {
    send_scratch: Vec<u8>,
    nonces: NonceGenerator,
}

struct UdpReceiveState {
    recv_slots: [Vec<u8>; quinn::udp::BATCH_SIZE],
}

/// A masking wrapper around quinn's UDP socket abstraction.
pub struct MaskedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    server_filter: bool,
    send: Mutex<UdpSendState>,
    receive: Mutex<UdpReceiveState>,
}

impl std::fmt::Debug for MaskedUdpSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MaskedUdpSocket")
            .finish_non_exhaustive()
    }
}

impl MaskedUdpSocket {
    /// Wraps `inner` for the client role.
    pub fn new_client(
        inner: Arc<dyn AsyncUdpSocket>,
        keys: &MaskKeys,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Arc<Self> {
        Self::new(inner, keys.udp_c2s(), keys.udp_s2c(), UdpRole::Client, rng)
    }

    /// Wraps `inner` for the server role (with the ingress version filter).
    pub fn new_server(
        inner: Arc<dyn AsyncUdpSocket>,
        keys: &MaskKeys,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Arc<Self> {
        Self::new(inner, keys.udp_s2c(), keys.udp_c2s(), UdpRole::Server, rng)
    }

    fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        send_key: [u8; 32],
        recv_key: [u8; 32],
        role: UdpRole,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            send_key: Zeroizing::new(send_key),
            recv_key: Zeroizing::new(recv_key),
            server_filter: role == UdpRole::Server,
            send: Mutex::new(UdpSendState {
                send_scratch: Vec::new(),
                nonces: NonceGenerator::new(rng),
            }),
            receive: Mutex::new(UdpReceiveState {
                recv_slots: std::array::from_fn(|_| Vec::new()),
            }),
        })
    }

    /// The masking overhead per segment; callers reduce their UDP payload
    /// limit (`max_udp_payload_size`) by this amount.
    pub const fn segment_overhead() -> usize {
        UDP_SEGMENT_OVERHEAD
    }

    fn decode_datagram(
        &self,
        storage: &[u8],
        wire_meta: RecvMeta,
        max_wire_len: usize,
        out: &mut [u8],
    ) -> io::Result<Option<RecvMeta>> {
        let wire_stride = wire_meta.stride;
        if wire_meta.len == 0
            || wire_meta.len > max_wire_len
            || wire_stride <= UDP_SEGMENT_OVERHEAD
            || wire_stride > wire_meta.len
        {
            return Ok(None);
        }
        let final_wire_len = wire_meta.len % wire_stride;
        // A trailing segment shorter than or equal to the nonce overhead is
        // garbage padding: trim it instead of discarding valid preceding segments.
        let wire_len = if final_wire_len != 0 && final_wire_len <= UDP_SEGMENT_OVERHEAD {
            wire_meta.len - final_wire_len
        } else {
            wire_meta.len
        };
        let segment_count = wire_len.div_ceil(wire_stride);
        let Some(nonce_bytes) = segment_count.checked_mul(UDP_SEGMENT_OVERHEAD) else {
            return Ok(None);
        };
        let Some(expected_len) = wire_len.checked_sub(nonce_bytes) else {
            return Ok(None);
        };
        if expected_len == 0 || expected_len > out.len() {
            return Ok(None);
        }
        let decoded_stride = wire_stride - UDP_SEGMENT_OVERHEAD;
        let mut decoded_len = 0_usize;
        for wire in storage[..wire_len].chunks(wire_stride) {
            let (nonce, encrypted) = wire.split_at(NONCE_LEN);
            let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("fixed nonce prefix");
            let mut cipher = ChaCha20::new(&Key::from(*self.recv_key), &Nonce::from(*nonce));
            let end = decoded_len + encrypted.len();
            cipher
                .try_apply_keystream_b2b(encrypted, &mut out[decoded_len..end])
                .map_err(|_| io::Error::other("UDP segment exceeds ChaCha20 keystream limit"))?;
            if self.server_filter && !supported_quic_packet(&out[decoded_len..end]) {
                continue;
            }
            decoded_len = end;
        }
        if decoded_len == 0 {
            return Ok(None);
        }
        Ok(Some(RecvMeta {
            addr: wire_meta.addr,
            len: decoded_len,
            stride: decoded_stride.min(decoded_len),
            ecn: wire_meta.ecn,
            dst_ip: wire_meta.dst_ip,
        }))
    }
}

/// Builds a [`quinn::EndpointConfig`] whose maximum accepted UDP payload size
/// is reduced by [`UDP_SEGMENT_OVERHEAD`] so masked datagrams stay within the
/// default endpoint MTU budget.
pub fn masked_endpoint_config() -> Result<quinn::EndpointConfig, quinn::ConfigError> {
    let mut config = quinn::EndpointConfig::default();
    let overhead =
        u64::try_from(UDP_SEGMENT_OVERHEAD).map_err(|_| quinn::ConfigError::OutOfBounds)?;
    let maximum = config
        .get_max_udp_payload_size()
        .checked_sub(overhead)
        .ok_or(quinn::ConfigError::OutOfBounds)?;
    let maximum = u16::try_from(maximum)?;
    config.max_udp_payload_size(maximum)?;
    Ok(config)
}

/// Caps MTU discovery below the unmasked carrier's budget by the per-segment
/// masking overhead, so a masked datagram (segment + nonce) never exceeds the
/// path MTU the plain carrier would have used. QUIC's clamped initial/min MTU
/// (1200) stays under every realistic path MTU even with the overhead added.
pub fn apply_masked_mtu(transport: &mut quinn::TransportConfig) {
    let mut discovery = quinn::MtuDiscoveryConfig::default();
    discovery.upper_bound(1452 - UDP_SEGMENT_OVERHEAD as u16);
    transport.mtu_discovery_config(Some(discovery));
}

/// Long-header packets must carry a version quinn supports. Version 0
/// (Version Negotiation) from a client is dropped: an unauthenticated peer
/// must not elicit any response, let alone a version negotiation.
fn supported_quic_packet(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    if packet[0] & 0x80 == 0 {
        // Short header: trust QUIC's own integrity checks downstream.
        return true;
    }
    if packet.len() < 5 {
        return false;
    }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    quinn_proto::DEFAULT_SUPPORTED_VERSIONS.contains(&version)
}

impl AsyncUdpSocket for MaskedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let plain_stride = transmit.segment_size.unwrap_or(transmit.contents.len());
        if plain_stride == 0 || transmit.contents.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty UDP datagram or zero-length GSO segment size",
            ));
        }
        let segments = transmit.contents.len().div_ceil(plain_stride);
        let overhead = segments
            .checked_mul(UDP_SEGMENT_OVERHEAD)
            .ok_or_else(|| io::Error::other("UDP datagram length overflow"))?;
        let wire_len = transmit
            .contents
            .len()
            .checked_add(overhead)
            .ok_or_else(|| io::Error::other("UDP datagram length overflow"))?;
        let wire_stride = transmit
            .segment_size
            .map(|size| {
                size.checked_add(UDP_SEGMENT_OVERHEAD)
                    .ok_or_else(|| io::Error::other("UDP segment length overflow"))
            })
            .transpose()?;

        let mut send_state = self
            .send
            .lock()
            .map_err(|_| io::Error::other("udp send state poisoned"))?;
        let UdpSendState {
            send_scratch,
            nonces,
        } = &mut *send_state;
        if send_scratch.len() < wire_len {
            send_scratch.resize(wire_len, 0);
        }
        let mut wire_offset = 0_usize;
        for plain in transmit.contents.chunks(plain_stride) {
            let wire_end = wire_offset + NONCE_LEN + plain.len();
            let (nonce_slot, payload_slot) =
                send_scratch[wire_offset..wire_end].split_at_mut(NONCE_LEN);
            let nonce = nonces.next();
            nonce_slot.copy_from_slice(&nonce);
            let mut cipher = ChaCha20::new(&Key::from(*self.send_key), &Nonce::from(nonce));
            cipher
                .try_apply_keystream_b2b(plain, payload_slot)
                .map_err(|_| io::Error::other("UDP segment exceeds ChaCha20 keystream limit"))?;
            wire_offset = wire_end;
        }
        debug_assert_eq!(wire_offset, wire_len);
        let masked = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &send_scratch[..wire_len],
            segment_size: wire_stride,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&masked)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty receive buffers",
            )));
        }
        let receive_count = bufs.len().min(meta.len()).min(quinn::udp::BATCH_SIZE);
        let max_segments = self.inner.max_receive_segments().max(1);
        let Some(nonce_overhead) = UDP_SEGMENT_OVERHEAD.checked_mul(max_segments) else {
            return Poll::Ready(Err(io::Error::other("UDP receive buffer length overflow")));
        };
        let Ok(mut receive_state) = self.receive.lock() else {
            return Poll::Ready(Err(io::Error::other("udp receive state poisoned")));
        };
        let mut wire_lengths = [0_usize; quinn::udp::BATCH_SIZE];
        for index in 0..receive_count {
            let Some(wire_len) = bufs[index].len().checked_add(nonce_overhead) else {
                return Poll::Ready(Err(io::Error::other("UDP receive buffer length overflow")));
            };
            wire_lengths[index] = wire_len;
            if receive_state.recv_slots[index].len() < wire_len {
                receive_state.recv_slots[index].resize(wire_len, 0);
            }
        }
        let mut slot_index = 0_usize;
        let mut wire_bufs = receive_state.recv_slots.each_mut().map(|slot| {
            let wire_len = wire_lengths[slot_index];
            slot_index += 1;
            std::io::IoSliceMut::new(&mut slot[..wire_len])
        });
        let received = match self.inner.poll_recv(
            cx,
            &mut wire_bufs[..receive_count],
            &mut meta[..receive_count],
        ) {
            Poll::Ready(Ok(received)) => received.min(receive_count),
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        let mut output = 0_usize;
        for index in 0..received {
            if let Some(decoded_meta) = self.decode_datagram(
                &receive_state.recv_slots[index],
                meta[index],
                wire_lengths[index],
                &mut bufs[output],
            )? {
                meta[output] = decoded_meta;
                output += 1;
            }
        }
        if output > 0 {
            return Poll::Ready(Ok(output));
        }
        // Every datagram in this batch was dropped (bad mask or, on the
        // server, an unsupported version). Yield to avoid starving co-scheduled
        // tasks if the inner socket stays readable.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use std::{io::IoSliceMut, net::SocketAddr, pin::Pin, sync::Arc, task::Poll, time::Duration};

    use chacha20::{ChaCha20, Key, KeyIvInit, Nonce, cipher::StreamCipher};
    use quinn::{
        AsyncUdpSocket, UdpPoller,
        udp::{RecvMeta, Transmit},
    };
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::{MaskedUdpSocket, UDP_SEGMENT_OVERHEAD};
    use crate::{MaskKeys, NONCE_LEN};

    fn keys() -> MaskKeys {
        MaskKeys::derive(b"udp-test", b"0123456789abcdef0123456789abcdef")
    }

    fn transmit(contents: &[u8], destination: SocketAddr) -> Transmit<'_> {
        Transmit {
            destination,
            ecn: None,
            contents,
            segment_size: None,
            src_ip: None,
        }
    }

    /// Minimal tokio-backed stand-in for quinn's real socket: one datagram
    /// per receive slot, no GSO/GRO (single-segment paths; the multi-segment
    /// stride math is exercised via a synthetic stride below).
    #[derive(Debug)]
    struct LoopbackSocket {
        socket: tokio::net::UdpSocket,
        // A blocking clone for the sync `try_send` path: loopback sends of
        // test-sized datagrams complete immediately, and tokio's cold
        // readiness state would otherwise surface WouldBlock spuriously.
        sender: std::net::UdpSocket,
    }

    impl AsyncUdpSocket for LoopbackSocket {
        fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn UdpPoller>> {
            unimplemented!("tests only use try_send/poll_recv")
        }

        fn try_send(&self, transmit_data: &Transmit<'_>) -> std::io::Result<()> {
            self.sender
                .send_to(transmit_data.contents, transmit_data.destination)
                .map(|_| ())
        }

        fn poll_recv(
            &self,
            cx: &mut std::task::Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<std::io::Result<usize>> {
            loop {
                let mut buffer = vec![0_u8; bufs[0].len()];
                match self.socket.try_recv_from(&mut buffer) {
                    Ok((len, addr)) => {
                        bufs[0][..len].copy_from_slice(&buffer[..len]);
                        meta[0] = RecvMeta {
                            addr,
                            len,
                            stride: len,
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => return Poll::Ready(Err(err)),
                }
                std::task::ready!(self.socket.poll_recv_ready(cx))?;
            }
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            self.socket.local_addr()
        }
    }

    #[allow(clippy::unused_async)] // signature symmetry with the await-using callers
    async fn wrapped_pair() -> (Arc<MaskedUdpSocket>, Arc<MaskedUdpSocket>, SocketAddr) {
        let client_raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_blocking = client_raw.try_clone().unwrap();
        client_raw.set_nonblocking(true).unwrap();
        let server_raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_blocking = server_raw.try_clone().unwrap();
        server_raw.set_nonblocking(true).unwrap();
        let server_addr = server_raw.local_addr().unwrap();
        let client_socket = Arc::new(LoopbackSocket {
            socket: tokio::net::UdpSocket::from_std(client_raw).unwrap(),
            sender: client_blocking,
        });
        let server_socket = Arc::new(LoopbackSocket {
            socket: tokio::net::UdpSocket::from_std(server_raw).unwrap(),
            sender: server_blocking,
        });
        let keys = keys();
        let mut rng = StdRng::seed_from_u64(7);
        let client = MaskedUdpSocket::new_client(
            Arc::clone(&client_socket) as Arc<dyn AsyncUdpSocket>,
            &keys,
            &mut rng,
        );
        let server = MaskedUdpSocket::new_server(
            Arc::clone(&server_socket) as Arc<dyn AsyncUdpSocket>,
            &keys,
            &mut rng,
        );
        (client, server, server_addr)
    }

    async fn poll_one(
        socket: &MaskedUdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<Option<(usize, RecvMeta)>> {
        let mut meta = [RecvMeta::default()];
        let mut slices = [IoSliceMut::new(buf)];
        let result = std::future::poll_fn(|cx| {
            AsyncUdpSocket::poll_recv(socket, cx, &mut slices, &mut meta)
        })
        .await?;
        if result == 0 {
            return Ok(None);
        }
        Ok(Some((meta[0].len, meta[0])))
    }

    #[tokio::test]
    async fn segments_round_trip_and_wire_is_masked() {
        let (client, server, server_addr) = wrapped_pair().await;

        // Observe raw ciphertext through an unmasked sink socket.
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = sink.local_addr().unwrap();
        let plaintext = b"a-quic-packet-body".to_vec();
        client.try_send(&transmit(&plaintext, sink_addr)).unwrap();
        let mut wire = vec![0_u8; 1500];
        let (wire_len, _) = sink.recv_from(&mut wire).await.unwrap();
        wire.truncate(wire_len);
        assert_eq!(wire.len(), plaintext.len() + UDP_SEGMENT_OVERHEAD);
        assert_ne!(&wire[UDP_SEGMENT_OVERHEAD..], &plaintext[..]);

        // The server decodes an identically masked datagram.
        client.try_send(&transmit(&plaintext, server_addr)).unwrap();
        let mut received = vec![0_u8; 1500];
        let (len, meta) =
            tokio::time::timeout(Duration::from_secs(3), poll_one(&server, &mut received))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(&received[..len], &plaintext[..]);
        assert_eq!(len, plaintext.len());
        assert!(meta.addr.is_ipv4());
    }

    #[tokio::test]
    async fn server_drops_unsupported_versions_silently() {
        let (client, server, server_addr) = wrapped_pair().await;
        for version in [9_u32, 0_u32] {
            let mut packet = vec![0xff_u8];
            packet.extend_from_slice(&version.to_be_bytes());
            packet.extend_from_slice(&[0_u8; 32]);
            client.try_send(&transmit(&packet, server_addr)).unwrap();
        }
        let mut received = vec![0_u8; 1500];
        let polled =
            tokio::time::timeout(Duration::from_millis(200), poll_one(&server, &mut received))
                .await;
        assert!(
            polled.is_err(),
            "unsupported versions and version 0 must be dropped without a response"
        );
    }

    #[tokio::test]
    async fn server_accepts_supported_version_long_header() {
        let (client, server, server_addr) = wrapped_pair().await;
        let mut packet = vec![0xff_u8];
        packet.extend_from_slice(&1_u32.to_be_bytes()); // QUIC v1
        packet.extend_from_slice(&[5_u8; 40]);
        client.try_send(&transmit(&packet, server_addr)).unwrap();
        let mut received = vec![0_u8; 1500];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(3), poll_one(&server, &mut received))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(&received[..len], &packet[..]);
    }

    #[test]
    fn nonce_generator_cycles_and_is_unique() {
        let mut rng = StdRng::seed_from_u64(11);
        let mut generator = super::NonceGenerator::new(&mut rng);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            // Force frequent refills by draining through many nonces.
            let nonce = generator.next();
            assert!(seen.insert(nonce), "nonces must never repeat");
        }
    }

    use std::collections::VecDeque;
    use std::future::poll_fn;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    use super::{UdpRole, masked_endpoint_config};

    #[derive(Debug, Default)]
    struct FakeUdpSocket {
        sent: StdMutex<Vec<(Vec<u8>, Option<usize>)>>,
        receive: StdMutex<VecDeque<(Vec<u8>, RecvMeta)>>,
        receive_lengths: StdMutex<Vec<usize>>,
        flood_until_stopped: Option<Arc<AtomicBool>>,
    }

    #[derive(Debug)]
    struct ReadyPoller;

    impl std::future::Future for ReadyPoller {
        type Output = std::io::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(Ok(()))
        }
    }

    impl UdpPoller for ReadyPoller {
        fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncUdpSocket for FakeUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(ReadyPoller)
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
            self.sent
                .lock()
                .unwrap()
                .push((transmit.contents.to_vec(), transmit.segment_size));
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<std::io::Result<usize>> {
            if let Some(stop_flood) = &self.flood_until_stopped {
                if !stop_flood.load(Ordering::Acquire) {
                    // Emit a valid-length wire frame whose decrypted payload has an
                    // unsupported QUIC version (version 0), simulating an attack flood.
                    let key = keys().udp_c2s();
                    let nonce = [0x42_u8; NONCE_LEN];
                    let mut wire = Vec::with_capacity(NONCE_LEN + 8);
                    wire.extend_from_slice(&nonce);
                    let mut plain = [0xc0_u8, 0, 0, 0, 0, 1, 2, 3];
                    ChaCha20::new(&Key::from(key), &Nonce::from(nonce)).apply_keystream(&mut plain);
                    wire.extend_from_slice(&plain);
                    bufs[0][..wire.len()].copy_from_slice(&wire);
                    meta[0] = RecvMeta {
                        addr: "127.0.0.1:9999".parse().unwrap(),
                        len: wire.len(),
                        stride: wire.len(),
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
            }
            let mut receive = self.receive.lock().unwrap();
            let mut count = 0_usize;
            for (buf, output_meta) in bufs.iter_mut().zip(meta.iter_mut()) {
                let Some((packet, packet_meta)) = receive.pop_front() else {
                    break;
                };
                self.receive_lengths.lock().unwrap().push(buf.len());
                let copy_len = packet.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&packet[..copy_len]);
                *output_meta = packet_meta;
                count += 1;
            }
            if count == 0 {
                Poll::Pending
            } else {
                Poll::Ready(Ok(count))
            }
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        fn max_transmit_segments(&self) -> usize {
            2
        }

        fn max_receive_segments(&self) -> usize {
            2
        }
    }

    fn queue_masked_segments(
        raw: &FakeUdpSocket,
        key: [u8; 32],
        plain: &[u8],
        stride: usize,
        addr: &str,
    ) {
        let mut wire = Vec::new();
        for (index, segment) in plain.chunks(stride).enumerate() {
            let nonce = [index as u8; NONCE_LEN];
            wire.extend_from_slice(&nonce);
            let start = wire.len();
            wire.extend_from_slice(segment);
            ChaCha20::new(&Key::from(key), &Nonce::from(nonce)).apply_keystream(&mut wire[start..]);
        }
        let len = wire.len();
        raw.receive.lock().unwrap().push_back((
            wire,
            RecvMeta {
                addr: addr.parse().unwrap(),
                len,
                stride: (stride + UDP_SEGMENT_OVERHEAD).min(len),
                ecn: Some(quinn::udp::EcnCodepoint::Ect0),
                dst_ip: Some("127.0.0.9".parse().unwrap()),
            },
        ));
    }

    #[test]
    fn masked_endpoint_config_reserves_udp_segment_overhead() {
        let plain = quinn::EndpointConfig::default();
        let masked = masked_endpoint_config().unwrap();
        assert_eq!(
            masked.get_max_udp_payload_size() + UDP_SEGMENT_OVERHEAD as u64,
            plain.get_max_udp_payload_size()
        );
        assert_eq!(masked.get_max_udp_payload_size(), 1460);
    }

    #[test]
    fn try_send_validates_inputs_before_locking_send() {
        let raw = Arc::new(FakeUdpSocket::default());
        let keys = keys();
        let mut rng = StdRng::seed_from_u64(1);
        let socket = MaskedUdpSocket::new_client(
            Arc::clone(&raw) as Arc<dyn AsyncUdpSocket>,
            &keys,
            &mut rng,
        );
        let destination: SocketAddr = "127.0.0.1:2".parse().unwrap();

        // Hold `send` mutex on the same thread: input validation must reject
        // immediately before attempting to acquire `socket.send`.
        let _send_guard = socket.send.lock().unwrap();
        for transmit_data in [
            Transmit {
                destination,
                ecn: None,
                contents: &[],
                segment_size: None,
                src_ip: None,
            },
            Transmit {
                destination,
                ecn: None,
                contents: b"abc",
                segment_size: Some(0),
                src_ip: None,
            },
            Transmit {
                destination,
                ecn: None,
                contents: &[],
                segment_size: Some(8),
                src_ip: None,
            },
        ] {
            let err = socket.try_send(&transmit_data).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn send_and_receive_locks_are_independent() {
        let raw = Arc::new(FakeUdpSocket::default());
        let keys = keys();
        let mut rng = StdRng::seed_from_u64(2);
        let socket = MaskedUdpSocket::new_client(
            Arc::clone(&raw) as Arc<dyn AsyncUdpSocket>,
            &keys,
            &mut rng,
        );
        let destination: SocketAddr = "127.0.0.1:2".parse().unwrap();

        {
            let _recv_guard = socket.receive.lock().unwrap();
            socket.try_send(&transmit(b"hello", destination)).unwrap();
        }
        assert_eq!(raw.sent.lock().unwrap().len(), 1);

        queue_masked_segments(&raw, keys.udp_s2c(), b"reply", 5, "127.0.0.1:2");
        {
            let _send_guard = socket.send.lock().unwrap();
            let mut buf = [0_u8; 16];
            let mut bufs = [IoSliceMut::new(&mut buf)];
            let mut meta = [RecvMeta::default()];
            let mut cx = Context::from_waker(Waker::noop());
            let polled = socket.poll_recv(&mut cx, &mut bufs, &mut meta);
            assert!(matches!(polled, Poll::Ready(Ok(1))));
            assert_eq!(&buf[..5], b"reply");
        }
    }

    async fn assert_server_gro_filtering(
        raw: &Arc<FakeUdpSocket>,
        keys: &MaskKeys,
        rng: &mut StdRng,
    ) {
        let server =
            MaskedUdpSocket::new_server(Arc::clone(raw) as Arc<dyn AsyncUdpSocket>, keys, rng);
        let mut accepted = vec![0xc0_u8];
        accepted.extend_from_slice(&quinn_proto::DEFAULT_SUPPORTED_VERSIONS[0].to_be_bytes());
        accepted.extend_from_slice(&[1, 2, 3]);
        let rejected = [0xc0_u8, 0xff, 0xff, 0xff, 0xff, 4, 5, 6];
        let combined = [rejected.as_slice(), &accepted].concat();
        queue_masked_segments(raw, keys.udp_c2s(), &combined, 8, "127.0.0.2:2345");
        let mut out_srv = [0xa7_u8; 16];
        let mut bufs_srv = [IoSliceMut::new(&mut out_srv)];
        let mut meta_srv = [RecvMeta::default()];
        let count_srv = poll_fn(|cx| server.poll_recv(cx, &mut bufs_srv, &mut meta_srv))
            .await
            .unwrap();
        assert_eq!(count_srv, 1);
        assert_eq!(&out_srv[..accepted.len()], accepted);
        assert_eq!(meta_srv[0].len, accepted.len());
        assert_eq!(meta_srv[0].stride, 8);
        assert_eq!(meta_srv[0].addr, "127.0.0.2:2345".parse().unwrap());
        assert_eq!(meta_srv[0].ecn, Some(quinn::udp::EcnCodepoint::Ect0));
        assert_eq!(meta_srv[0].dst_ip, Some("127.0.0.9".parse().unwrap()));
    }

    #[tokio::test]
    async fn try_send_and_poll_recv_preserve_gso_gro_boundaries_and_trim_padding() {
        let raw = Arc::new(FakeUdpSocket::default());
        let keys = keys();
        let mut rng = StdRng::seed_from_u64(3);
        let client = MaskedUdpSocket::new(
            Arc::clone(&raw) as Arc<dyn AsyncUdpSocket>,
            keys.udp_c2s(),
            keys.udp_c2s(),
            UdpRole::Client,
            &mut rng,
        );
        let destination: SocketAddr = "127.0.0.1:2".parse().unwrap();

        // 1. GSO segment preservation across uneven final segment.
        for plain in [b"abcdef".as_slice(), b"abcde".as_slice()] {
            client
                .try_send(&Transmit {
                    destination,
                    ecn: None,
                    contents: plain,
                    segment_size: Some(3),
                    src_ip: None,
                })
                .unwrap();
            let (wire, stride) = raw.sent.lock().unwrap().pop().unwrap();
            assert_eq!(stride, Some(3 + UDP_SEGMENT_OVERHEAD));
            assert_eq!(wire.len(), plain.len() + 2 * UDP_SEGMENT_OVERHEAD);
            assert_ne!(&wire[..NONCE_LEN], &wire[15..15 + NONCE_LEN]);

            let wire_len = wire.len();
            raw.receive.lock().unwrap().push_back((
                wire,
                RecvMeta {
                    addr: destination,
                    len: wire_len,
                    stride: 15,
                    ecn: None,
                    dst_ip: None,
                },
            ));
            let mut output = [0xa7_u8; 6];
            let mut bufs = [IoSliceMut::new(&mut output)];
            let mut meta = [RecvMeta::default()];
            let count = poll_fn(|cx| client.poll_recv(cx, &mut bufs, &mut meta))
                .await
                .unwrap();
            assert_eq!(count, 1);
            assert_eq!(&output[..plain.len()], plain);
            assert!(output[plain.len()..].iter().all(|byte| *byte == 0xa7));
            assert_eq!(meta[0].len, plain.len());
            assert_eq!(meta[0].stride, 3);
        }

        // 2. Invalid frames (nonce-only, oversized expected_len > out.len(), stride <= 12,
        // stride > len, len > wire_lengths[i]) are discarded before valid data.
        let packet_meta = |len, stride| RecvMeta {
            addr: destination,
            len,
            stride,
            ecn: None,
            dst_ip: None,
        };
        raw.receive
            .lock()
            .unwrap()
            .push_back((vec![0; NONCE_LEN], packet_meta(NONCE_LEN, NONCE_LEN)));
        client
            .try_send(&transmit(b"oversized-payload", destination))
            .unwrap();
        let (oversized, _) = raw.sent.lock().unwrap().pop().unwrap();
        let oversized_len = oversized.len();
        raw.receive
            .lock()
            .unwrap()
            .push_back((oversized, packet_meta(oversized_len, oversized_len)));
        raw.receive
            .lock()
            .unwrap()
            .push_back((vec![0; 20], packet_meta(20, UDP_SEGMENT_OVERHEAD)));
        raw.receive
            .lock()
            .unwrap()
            .push_back((vec![0; 20], packet_meta(20, 21)));
        raw.receive
            .lock()
            .unwrap()
            .push_back((vec![0; 20], packet_meta(5 + NONCE_LEN * 2 + 1, 20)));

        // 3. Trailing <= 12B padding fragment on a GRO batch is trimmed, preserving valid prefix.
        queue_masked_segments(&raw, keys.udp_c2s(), b"valid", 5, "127.0.0.1:2");
        {
            let mut queue = raw.receive.lock().unwrap();
            let (mut padded_wire, mut padded_meta) = queue.pop_back().unwrap();
            padded_wire.extend_from_slice(&[0xee_u8; 7]);
            padded_meta.len += 7;
            queue.push_back((padded_wire, padded_meta));
        }

        let mut output = [0_u8; 5];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [RecvMeta::default()];
        let count = poll_fn(|cx| client.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(&output, b"valid");
        assert_eq!(meta[0].len, 5);

        // 4. Server-role per-segment GRO filtering + metadata preservation.
        assert_server_gro_filtering(&raw, &keys, &mut rng).await;
    }

    #[tokio::test]
    async fn poll_recv_reuses_slots_without_relaxing_receive_bounds_and_clamps_counts() {
        let raw = Arc::new(FakeUdpSocket::default());
        let keys = keys();
        let mut rng = StdRng::seed_from_u64(4);
        let socket = MaskedUdpSocket::new(
            Arc::clone(&raw) as Arc<dyn AsyncUdpSocket>,
            keys.udp_c2s(),
            keys.udp_c2s(),
            UdpRole::Client,
            &mut rng,
        );
        let destination: SocketAddr = "127.0.0.1:2".parse().unwrap();

        // Receive 32 -> 4 -> 48 bytes; verify inner receive slice length shrinks cleanly on 4-byte poll.
        queue_masked_segments(&raw, keys.udp_c2s(), &[0x5a; 32], 32, "127.0.0.1:2");
        let mut large_out = [0_u8; 32];
        let mut large_bufs = [IoSliceMut::new(&mut large_out)];
        let mut large_meta = [RecvMeta::default()];
        assert_eq!(
            poll_fn(|cx| socket.poll_recv(cx, &mut large_bufs, &mut large_meta))
                .await
                .unwrap(),
            1
        );
        assert_eq!(large_out, [0x5a; 32]);

        queue_masked_segments(&raw, keys.udp_c2s(), b"x", 1, "127.0.0.1:2");
        let mut small_out = [0xa7_u8; 4];
        let mut small_bufs = [IoSliceMut::new(&mut small_out)];
        let mut small_meta = [RecvMeta::default()];
        assert_eq!(
            poll_fn(|cx| socket.poll_recv(cx, &mut small_bufs, &mut small_meta))
                .await
                .unwrap(),
            1
        );
        assert_eq!(small_out, [b'x', 0xa7, 0xa7, 0xa7]);

        queue_masked_segments(&raw, keys.udp_c2s(), &[0xa5; 48], 48, "127.0.0.1:2");
        let mut grown_out = [0_u8; 48];
        let mut grown_bufs = [IoSliceMut::new(&mut grown_out)];
        let mut grown_meta = [RecvMeta::default()];
        assert_eq!(
            poll_fn(|cx| socket.poll_recv(cx, &mut grown_bufs, &mut grown_meta))
                .await
                .unwrap(),
            1
        );
        assert_eq!(grown_out, [0xa5; 48]);
        assert_eq!(
            *raw.receive_lengths.lock().unwrap(),
            [
                32 + 2 * UDP_SEGMENT_OVERHEAD,
                4 + 2 * UDP_SEGMENT_OVERHEAD,
                48 + 2 * UDP_SEGMENT_OVERHEAD
            ]
        );

        // Mismatched bufs.len() > meta.len() and > BATCH_SIZE must clamp without panic.
        let batch_plus = quinn::udp::BATCH_SIZE + 4;
        for _ in 0..batch_plus {
            queue_masked_segments(&raw, keys.udp_c2s(), b"ok", 2, "127.0.0.1:2");
        }
        let mut many_out = vec![[0_u8; 8]; batch_plus];
        let mut many_bufs: Vec<IoSliceMut<'_>> = many_out
            .iter_mut()
            .map(|slot| IoSliceMut::new(slot))
            .collect();
        let mut few_meta = [RecvMeta::default()];
        let count = poll_fn(|cx| socket.poll_recv(cx, &mut many_bufs, &mut few_meta))
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(&many_out[0][..2], b"ok");
        assert_eq!(few_meta[0].destination_port_check(), destination.port());
    }

    trait RecvMetaExt {
        fn destination_port_check(&self) -> u16;
    }

    impl RecvMetaExt for RecvMeta {
        fn destination_port_check(&self) -> u16 {
            self.addr.port()
        }
    }

    struct TestWake(AtomicUsize);

    impl std::task::Wake for TestWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn poll_recv_wakes_and_returns_pending_on_zero_produced_without_starving_tasks() {
        let raw = Arc::new(FakeUdpSocket::default());
        let keys = keys();
        let mut rng = StdRng::seed_from_u64(5);
        let socket = MaskedUdpSocket::new_server(
            Arc::clone(&raw) as Arc<dyn AsyncUdpSocket>,
            &keys,
            &mut rng,
        );

        let rejected = [0xc0_u8, 0xff, 0xff, 0xff, 0xff];
        queue_masked_segments(&raw, keys.udp_c2s(), &rejected, 5, "127.0.0.2:2");
        let mut output = [[0_u8; 16]; 2];
        let mut bufs = output.each_mut().map(|buf| IoSliceMut::new(buf));
        let mut meta = [RecvMeta::default(); 2];
        let wake_counter = Arc::new(TestWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake_counter));
        let mut cx = Context::from_waker(&waker);
        assert!(socket.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);

        // Subsequent batch compacts out invalid leading packet and delivers valid one.
        queue_masked_segments(&raw, keys.udp_c2s(), &rejected, 5, "127.0.0.2:2");
        queue_masked_segments(&raw, keys.udp_c2s(), &[0x40_u8, 1, 2, 3], 4, "127.0.0.3:3");
        assert_eq!(
            poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
                .await
                .unwrap(),
            1
        );
        assert_eq!(&bufs[0][..4], &[0x40, 1, 2, 3]);
        assert_eq!(meta[0].addr, "127.0.0.3:3".parse().unwrap());

        // Starvation check under continuous invalid-datagram flood on current_thread runtime:
        // co-scheduled task must run and flip `stop_flood`, allowing a valid packet through.
        let stop_flood = Arc::new(AtomicBool::new(false));
        let flood_raw = Arc::new(FakeUdpSocket {
            flood_until_stopped: Some(Arc::clone(&stop_flood)),
            ..FakeUdpSocket::default()
        });
        let flood_socket = MaskedUdpSocket::new_server(
            Arc::clone(&flood_raw) as Arc<dyn AsyncUdpSocket>,
            &keys,
            &mut rng,
        );
        let flood_task = tokio::spawn({
            let flood_socket = Arc::clone(&flood_socket);
            async move {
                let mut buf = [0_u8; 16];
                let mut bufs = [IoSliceMut::new(&mut buf)];
                let mut meta = [RecvMeta::default()];
                poll_fn(|cx| flood_socket.poll_recv(cx, &mut bufs, &mut meta)).await
            }
        });
        let stop_task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            queue_masked_segments(
                &flood_raw,
                keys.udp_c2s(),
                &[0x40_u8, 9, 8],
                3,
                "127.0.0.4:4",
            );
            stop_flood.store(true, Ordering::Release);
        });
        let (flood_res, stop_res) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(flood_task, stop_task)
        })
        .await
        .expect("poll_recv must yield and never starve co-scheduled tasks");
        stop_res.unwrap();
        assert_eq!(flood_res.unwrap().unwrap(), 1);
    }

    #[tokio::test]
    async fn server_gro_filtering_drops_middle_invalid_segment_and_short_long_headers() {
        assert!(!super::supported_quic_packet(&[0x80]));
        assert!(!super::supported_quic_packet(&[0xc0, 0x00, 0x00, 0x01]));

        let raw = Arc::new(FakeUdpSocket::default());
        let keys = keys();
        let mut rng = StdRng::seed_from_u64(9);
        let server = MaskedUdpSocket::new_server(
            Arc::clone(&raw) as Arc<dyn AsyncUdpSocket>,
            &keys,
            &mut rng,
        );

        let mut accepted_first = vec![0xc0_u8];
        accepted_first.extend_from_slice(&quinn_proto::DEFAULT_SUPPORTED_VERSIONS[0].to_be_bytes());
        accepted_first.extend_from_slice(&[1, 2, 3]);
        let rejected_mid = [0xc0_u8, 0xff, 0xff, 0xff, 0xff, 4, 5, 6];
        let mut accepted_last = vec![0xc0_u8];
        accepted_last.extend_from_slice(&quinn_proto::DEFAULT_SUPPORTED_VERSIONS[0].to_be_bytes());
        accepted_last.extend_from_slice(&[7, 8, 9]);
        let combined = [accepted_first.as_slice(), &rejected_mid, &accepted_last].concat();
        queue_masked_segments(&raw, keys.udp_c2s(), &combined, 8, "127.0.0.2:4567");

        let mut out = [0xa7_u8; 48];
        let mut bufs = [IoSliceMut::new(&mut out)];
        let mut meta = [RecvMeta::default()];
        let count = tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| server.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(meta[0].len, 16);
        assert_eq!(meta[0].stride, 8);
        assert_eq!(&bufs[0][..8], accepted_first.as_slice());
        assert_eq!(&bufs[0][8..16], accepted_last.as_slice());

        // Masked 4-byte long-header packet (< 5B) must be silently dropped (Poll::Pending).
        queue_masked_segments(
            &raw,
            keys.udp_c2s(),
            &[0xc0, 0x00, 0x00, 0x01],
            4,
            "127.0.0.2:4567",
        );
        let wake_counter = Arc::new(TestWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake_counter));
        let mut cx = Context::from_waker(&waker);
        assert!(server.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
    }
}
