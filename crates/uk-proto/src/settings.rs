//! UK SETTINGS payload support.

use std::collections::BTreeMap;

use bytes::{Buf, BufMut};

use crate::{ProtocolError, ProtocolResult, varint};

/// Known v0.1 setting keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum SettingKey {
    /// Maximum frame payload size.
    MaxFrameSize = 1,
    /// Maximum concurrent streams.
    MaxStreams = 2,
    /// Maximum UDP flows.
    MaxUdpFlows = 3,
    /// Whether QUIC DATAGRAM is supported.
    SupportsUdpDatagram = 4,
    /// Whether UDP-over-stream fallback is supported.
    SupportsUdpStreamFallback = 5,
    /// Idle timeout in seconds.
    IdleTimeoutSeconds = 6,
    /// Protocol revision.
    ProtocolRevision = 7,
}

impl TryFrom<u64> for SettingKey {
    type Error = ProtocolError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::MaxFrameSize),
            2 => Ok(Self::MaxStreams),
            3 => Ok(Self::MaxUdpFlows),
            4 => Ok(Self::SupportsUdpDatagram),
            5 => Ok(Self::SupportsUdpStreamFallback),
            6 => Ok(Self::IdleTimeoutSeconds),
            7 => Ok(Self::ProtocolRevision),
            _ => Err(ProtocolError::InvalidSettings("unknown setting key")),
        }
    }
}

/// SETTINGS payload values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    values: BTreeMap<SettingKey, u64>,
}

impl Settings {
    /// Stores `value` for `key`.
    pub fn set(&mut self, key: SettingKey, value: u64) {
        self.values.insert(key, value);
    }

    /// Gets a setting value by key.
    pub fn get(&self, key: SettingKey) -> Option<u64> {
        self.values.get(&key).copied()
    }

    /// Encodes settings into `dst`.
    pub fn encode(&self, dst: &mut impl BufMut) -> ProtocolResult<()> {
        varint::encode(self.values.len() as u64, dst)?;
        for (key, value) in &self.values {
            varint::encode(*key as u64, dst)?;
            varint::encode(*value, dst)?;
        }
        Ok(())
    }

    /// Decodes settings from `src`.
    pub fn decode(src: &mut impl Buf) -> ProtocolResult<Self> {
        let count = varint::decode(src)?;
        let count = usize::try_from(count).map_err(|_| ProtocolError::InvalidVarint)?;
        let mut settings = Self::default();
        for _ in 0..count {
            let key = varint::decode(src)?;
            let value = varint::decode(src)?;
            if let Ok(key) = SettingKey::try_from(key) {
                if settings.get(key).is_some() {
                    return Err(ProtocolError::InvalidSettings("duplicate setting key"));
                }
                settings.set(key, value);
            }
        }
        if src.has_remaining() {
            return Err(ProtocolError::InvalidSettings("trailing settings bytes"));
        }
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn roundtrips_settings() {
        let mut settings = Settings::default();
        settings.set(SettingKey::MaxFrameSize, 65_536);
        settings.set(SettingKey::ProtocolRevision, 1);

        let mut out = Vec::new();
        settings.encode(&mut out).unwrap();
        let mut bytes = Bytes::from(out);
        assert_eq!(Settings::decode(&mut bytes).unwrap(), settings);
    }

    #[test]
    fn ignores_unknown_optional_settings() {
        let mut bytes = Bytes::from_static(&[0x02, 0x01, 0x40, 0x80, 0x3f, 0x01]);
        let settings = Settings::decode(&mut bytes).unwrap();
        assert_eq!(settings.get(SettingKey::MaxFrameSize), Some(128));
    }

    #[test]
    fn rejects_trailing_settings_bytes() {
        let mut bytes = Bytes::from_static(&[0x01, 0x01, 0x40, 0x80, 0xff]);
        assert_eq!(
            Settings::decode(&mut bytes),
            Err(ProtocolError::InvalidSettings("trailing settings bytes"))
        );
    }

    #[test]
    fn rejects_duplicate_known_setting_keys() {
        let mut bytes = Bytes::from_static(&[0x02, 0x01, 0x40, 0x80, 0x01, 0x40, 0x81]);
        assert_eq!(
            Settings::decode(&mut bytes),
            Err(ProtocolError::InvalidSettings("duplicate setting key"))
        );
    }
}
