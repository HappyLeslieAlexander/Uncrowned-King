//! QUIC-style variable-length integer encoding.

use bytes::{Buf, BufMut};

use crate::{ProtocolError, ProtocolResult};

/// The largest value representable by a UK varint.
pub const MAX_VARINT: u64 = (1_u64 << 62) - 1;

/// Returns the encoded length in bytes for `value`.
pub fn encoded_len(value: u64) -> ProtocolResult<usize> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX_VARINT => Ok(8),
        _ => Err(ProtocolError::InvalidVarint),
    }
}

/// Encodes `value` into `dst` using the shortest legal representation.
pub fn encode(value: u64, dst: &mut impl BufMut) -> ProtocolResult<()> {
    match encoded_len(value)? {
        1 => dst.put_u8(value as u8),
        2 => dst.put_u16((value as u16) | 0x4000),
        4 => dst.put_u32((value as u32) | 0x8000_0000),
        8 => dst.put_u64(value | 0xc000_0000_0000_0000),
        _ => unreachable!("encoded_len only returns 1, 2, 4, or 8"),
    }
    Ok(())
}

/// Decodes one varint from `src`.
pub fn decode(src: &mut impl Buf) -> ProtocolResult<u64> {
    if !src.has_remaining() {
        return Err(ProtocolError::Truncated);
    }

    let first = src.chunk()[0];
    let len = 1_usize << (first >> 6);
    if src.remaining() < len {
        return Err(ProtocolError::Truncated);
    }

    let value = match len {
        1 => u64::from(src.get_u8() & 0x3f),
        2 => u64::from(src.get_u16() & 0x3fff),
        4 => u64::from(src.get_u32() & 0x3fff_ffff),
        8 => src.get_u64() & 0x3fff_ffff_ffff_ffff,
        _ => unreachable!("QUIC varint prefix only permits 1, 2, 4, or 8 bytes"),
    };
    // QUIC (RFC 9000 §16) allows a value to be encoded in any width whose
    // prefix can hold it, so `0xc0 00 00 00 00 00 00 01` is a legal spelling of
    // `1` there. UK's parsers are deliberately stricter (whitepaper §20): one
    // logical frame must have exactly one wire form, otherwise byte-level
    // dedup and fingerprinting are defeated and length limits derived from the
    // minimal encoding (`MIN_TCP_RELAY_FRAME_SIZE`) stop bounding the wire size.
    if encoded_len(value)? != len {
        return Err(ProtocolError::InvalidVarint);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn encodes_known_vectors() {
        let mut out = Vec::new();
        encode(37, &mut out).unwrap();
        assert_eq!(out, [0x25]);

        out.clear();
        encode(15_293, &mut out).unwrap();
        assert_eq!(out, [0x7b, 0xbd]);

        out.clear();
        encode(494_878_333, &mut out).unwrap();
        assert_eq!(out, [0x9d, 0x7f, 0x3e, 0x7d]);
    }

    #[test]
    fn roundtrips_boundaries() {
        for value in [
            0,
            37,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            MAX_VARINT,
        ] {
            let mut out = Vec::new();
            encode(value, &mut out).unwrap();
            let mut bytes = Bytes::from(out);
            assert_eq!(decode(&mut bytes).unwrap(), value);
            assert!(!bytes.has_remaining());
        }
    }

    #[test]
    fn rejects_too_large_value() {
        assert_eq!(
            encoded_len(MAX_VARINT + 1),
            Err(ProtocolError::InvalidVarint)
        );
    }

    #[test]
    fn rejects_truncated_input() {
        let mut bytes = Bytes::from_static(&[0x40]);
        assert_eq!(decode(&mut bytes), Err(ProtocolError::Truncated));
    }

    #[test]
    fn rejects_non_minimal_encodings() {
        // Every over-wide spelling of a value RFC 9000 would accept.
        for encoded in [
            [0x40, 0x01].as_slice(),
            [0x80, 0x00, 0x00, 0x01].as_slice(),
            [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01].as_slice(),
            [0x80, 0x00, 0x3f, 0xff].as_slice(),
            [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xff].as_slice(),
            [0xc0, 0x00, 0x00, 0x00, 0x3f, 0xff, 0xff, 0xff].as_slice(),
        ] {
            let mut bytes = Bytes::from_static(encoded);
            assert_eq!(decode(&mut bytes), Err(ProtocolError::InvalidVarint));
        }
    }

    #[test]
    fn accepts_minimal_encodings_at_each_width_boundary() {
        for (value, encoded) in [
            (0_u64, [0x00].as_slice()),
            (63, [0x3f].as_slice()),
            (64, [0x40, 0x40].as_slice()),
            (16_383, [0x7f, 0xff].as_slice()),
            (16_384, [0x80, 0x00, 0x40, 0x00].as_slice()),
            (1_073_741_823, [0xbf, 0xff, 0xff, 0xff].as_slice()),
            (
                1_073_741_824,
                [0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00].as_slice(),
            ),
        ] {
            let mut bytes = Bytes::from_static(encoded);
            assert_eq!(decode(&mut bytes).unwrap(), value);
        }
    }
}
