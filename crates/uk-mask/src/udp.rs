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

struct UdpIo {
    send_scratch: Vec<u8>,
    /// One scratch buffer per caller receive slot, sized for the caller's
    /// buffer plus per-segment masking overhead.
    recv_slots: Vec<Vec<u8>>,
    recv_metas: Vec<RecvMeta>,
    decoded: Vec<u8>,
}

/// A masking wrapper around quinn's UDP socket abstraction.
pub struct MaskedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    server_filter: bool,
    nonces: Mutex<NonceGenerator>,
    io: Mutex<UdpIo>,
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
            nonces: Mutex::new(NonceGenerator::new(rng)),
            io: Mutex::new(UdpIo {
                send_scratch: Vec::new(),
                recv_slots: Vec::new(),
                recv_metas: Vec::new(),
                decoded: Vec::new(),
            }),
        })
    }

    /// The masking overhead per segment; callers reduce their UDP payload
    /// limit (`max_udp_payload_size`) by this amount.
    pub const fn segment_overhead() -> usize {
        UDP_SEGMENT_OVERHEAD
    }

    fn mask_segment(&self, scratch: &mut Vec<u8>, plaintext: &[u8], nonce: [u8; NONCE_LEN]) {
        let mut cipher = ChaCha20::new(&Key::from(*self.send_key), &Nonce::from(nonce));
        scratch.extend_from_slice(&nonce);
        let payload_start = scratch.len();
        scratch.extend_from_slice(plaintext);
        cipher
            .try_apply_keystream(&mut scratch[payload_start..])
            .expect("segment size is bounded by the UDP payload limit");
    }

    /// Unmasks one wire segment into `out`. Returns `None` when the segment
    /// is too short to carry a nonce.
    fn unmask_segment<'out>(
        &self,
        segment: &[u8],
        out: &'out mut Vec<u8>,
    ) -> Option<&'out mut [u8]> {
        if segment.len() <= NONCE_LEN {
            return None;
        }
        let (nonce, payload) = segment.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
        let start = out.len();
        out.extend_from_slice(payload);
        let mut cipher = ChaCha20::new(&Key::from(*self.recv_key), &Nonce::from(nonce));
        cipher
            .try_apply_keystream(&mut out[start..])
            .expect("segment size is bounded by the UDP payload limit");
        let end = out.len();
        Some(&mut out[start..end])
    }
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
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| io::Error::other("nonce generator poisoned"))?;
        let mut io_state = self
            .io
            .lock()
            .map_err(|_| io::Error::other("udp io state poisoned"))?;
        io_state.send_scratch.clear();
        let wire_segment_size = match transmit.segment_size {
            None => {
                let nonce = nonces.next();
                self.mask_segment(&mut io_state.send_scratch, transmit.contents, nonce);
                None
            }
            Some(segment_size) => {
                if segment_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "zero-length GSO segment size",
                    ));
                }
                for segment in transmit.contents.chunks(segment_size) {
                    let nonce = nonces.next();
                    self.mask_segment(&mut io_state.send_scratch, segment, nonce);
                }
                Some(segment_size + UDP_SEGMENT_OVERHEAD)
            }
        };
        let masked = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &io_state.send_scratch,
            segment_size: wire_segment_size,
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
        let max_segments = self.inner.max_receive_segments().max(1);
        let Ok(mut io_state) = self.io.lock() else {
            return Poll::Ready(Err(io::Error::other("udp io state poisoned")));
        };
        // Split the guard's fields up front so the scratch slices, the
        // metadata vector, and the decoded staging buffer can be borrowed
        // independently below.
        let UdpIo {
            recv_slots,
            recv_metas,
            decoded,
            ..
        } = &mut *io_state;
        loop {
            if recv_slots.len() < bufs.len() {
                recv_slots.resize_with(bufs.len(), Vec::new);
            }
            if recv_metas.len() < bufs.len() {
                recv_metas.resize_with(bufs.len(), RecvMeta::default);
            }
            for (slot, buf) in recv_slots.iter_mut().zip(bufs.iter()) {
                let needed = buf.len() + UDP_SEGMENT_OVERHEAD * max_segments;
                if slot.len() < needed {
                    slot.resize(needed, 0);
                }
            }
            let received = {
                let mut slices: Vec<std::io::IoSliceMut<'_>> = recv_slots
                    .iter_mut()
                    .map(|slot| std::io::IoSliceMut::new(slot.as_mut_slice()))
                    .collect();
                let mut metas = std::mem::take(recv_metas);
                let result = self.inner.poll_recv(cx, &mut slices, &mut metas);
                *recv_metas = metas;
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(received)) => received,
                }
            };
            let mut produced = 0_usize;
            for slot_index in 0..received {
                let wire_meta = recv_metas[slot_index];
                let wire_len = wire_meta.len.min(recv_slots[slot_index].len());
                let wire = &recv_slots[slot_index][..wire_len];
                if wire.is_empty() || wire_meta.stride <= UDP_SEGMENT_OVERHEAD {
                    continue;
                }
                decoded.clear();
                for segment in wire.chunks(wire_meta.stride) {
                    let segment_start = decoded.len();
                    if self.unmask_segment(segment, decoded).is_none() {
                        continue;
                    }
                    if self.server_filter && !supported_quic_packet(&decoded[segment_start..]) {
                        decoded.truncate(segment_start);
                    }
                }
                if decoded.is_empty() {
                    continue;
                }
                let decoded_len = decoded.len();
                if decoded_len > bufs[produced].len() {
                    // Defensive: never overflow the caller's buffer.
                    continue;
                }
                bufs[produced][..decoded_len].copy_from_slice(decoded);
                meta[produced] = RecvMeta {
                    addr: wire_meta.addr,
                    len: decoded_len,
                    stride: (wire_meta.stride - UDP_SEGMENT_OVERHEAD).min(decoded_len),
                    ecn: wire_meta.ecn,
                    dst_ip: wire_meta.dst_ip,
                };
                produced += 1;
            }
            if produced > 0 {
                return Poll::Ready(Ok(produced));
            }
            // Every datagram in this batch was dropped (bad mask or, on the
            // server, an unsupported version). Poll again; once the inner
            // socket drains, its Pending re-arms the waker.
        }
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
    use std::{io::IoSliceMut, net::SocketAddr, sync::Arc, task::Poll, time::Duration};

    use quinn::{
        AsyncUdpSocket, UdpPoller,
        udp::{RecvMeta, Transmit},
    };
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::{MaskedUdpSocket, UDP_SEGMENT_OVERHEAD};
    use crate::MaskKeys;

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
}
