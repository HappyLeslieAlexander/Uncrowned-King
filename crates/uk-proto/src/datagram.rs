//! UDP-over-QUIC-DATAGRAM framing.
//!
//! When both peers advertise `supports_udp_datagram`, relayed UDP payloads may
//! travel over unreliable QUIC DATAGRAMs instead of `UDP_DATA` frames on the
//! control stream. A QUIC DATAGRAM has no in-band framing, so each relayed
//! datagram carries its flow id as a UK varint prefix followed by the raw UDP
//! payload:
//!
//! ```text
//! varint  flow_id
//! bytes   payload   (the remaining datagram bytes; may be empty)
//! ```
//!
//! The datagram carrier is unreliable and unordered, which matches UDP relay
//! semantics. Payloads that do not fit the negotiated QUIC datagram size fall
//! back to the reliable `UDP_DATA` frame path.

use bytes::{BufMut, Bytes};

use crate::{ProtocolResult, varint};

/// Returns the varint flow-id prefix length for `flow_id`, i.e. the datagram
/// framing overhead in bytes. Used to decide whether a payload fits the
/// negotiated maximum datagram size before falling back to the stream path.
pub fn overhead(flow_id: u64) -> ProtocolResult<usize> {
    varint::encoded_len(flow_id)
}

/// Encodes a relayed UDP datagram (`flow_id` prefix + `payload`) into `dst`.
pub fn encode(flow_id: u64, payload: &[u8], dst: &mut impl BufMut) -> ProtocolResult<()> {
    varint::encode(flow_id, dst)?;
    dst.put_slice(payload);
    Ok(())
}

/// Decodes a relayed UDP datagram into its flow id and payload.
///
/// The payload is the remainder of the datagram after the flow-id prefix and
/// may be empty (a zero-length UDP datagram is valid).
pub fn decode(mut datagram: Bytes) -> ProtocolResult<(u64, Bytes)> {
    let flow_id = varint::decode(&mut datagram)?;
    let payload = datagram.split_off(0);
    Ok((flow_id, payload))
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::ProtocolError;

    #[test]
    fn roundtrips_datagram() {
        let mut out = BytesMut::new();
        encode(5, b"hello", &mut out).unwrap();
        let (flow_id, payload) = decode(out.freeze()).unwrap();
        assert_eq!(flow_id, 5);
        assert_eq!(payload.as_ref(), b"hello");
    }

    #[test]
    fn roundtrips_empty_payload() {
        let mut out = BytesMut::new();
        encode(1, b"", &mut out).unwrap();
        let (flow_id, payload) = decode(out.freeze()).unwrap();
        assert_eq!(flow_id, 1);
        assert!(payload.is_empty());
    }

    #[test]
    fn roundtrips_large_flow_id() {
        let flow_id = 1_073_741_824; // forces an 8-byte varint prefix
        let mut out = BytesMut::new();
        encode(flow_id, b"payload", &mut out).unwrap();
        assert_eq!(overhead(flow_id).unwrap(), 8);
        let (decoded_id, payload) = decode(out.freeze()).unwrap();
        assert_eq!(decoded_id, flow_id);
        assert_eq!(payload.as_ref(), b"payload");
    }

    #[test]
    fn overhead_matches_varint_length() {
        assert_eq!(overhead(1).unwrap(), 1);
        assert_eq!(overhead(63).unwrap(), 1);
        assert_eq!(overhead(64).unwrap(), 2);
        assert_eq!(overhead(16_383).unwrap(), 2);
        assert_eq!(overhead(16_384).unwrap(), 4);
    }

    #[test]
    fn rejects_empty_datagram() {
        assert_eq!(decode(Bytes::new()), Err(ProtocolError::Truncated));
    }

    #[test]
    fn rejects_truncated_flow_id() {
        // A 2-byte varint prefix (0x40..) with only one byte present.
        assert_eq!(
            decode(Bytes::from_static(&[0x40])),
            Err(ProtocolError::Truncated)
        );
    }
}
