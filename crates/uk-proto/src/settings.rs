//! UK SETTINGS payload support.

use std::collections::BTreeMap;

use bytes::{Buf, BufMut};

use crate::{
    ProtocolError, ProtocolResult,
    frame::{DEFAULT_MAX_FRAME_SIZE, FrameLimits, MAX_FRAME_PAYLOAD_SIZE},
    tcp::MIN_TCP_RELAY_FRAME_SIZE,
    varint,
};

/// Default maximum concurrent streams when SETTINGS omits `max_streams`.
pub const DEFAULT_MAX_STREAMS: u64 = 64;

/// Wire protocol revision implemented by Uncrowned King v0.1.
pub const PROTOCOL_REVISION_V0_1: u64 = 1;

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

/// SETTINGS values after applying v0.1 defaults and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedSettings {
    /// Maximum frame payload size accepted by the peer.
    pub max_frame_size: u64,
    /// Maximum concurrent relay streams accepted by the peer.
    pub max_streams: u64,
    /// Maximum concurrent UDP relay flows accepted by the peer. Zero disables UDP relay.
    pub max_udp_flows: u64,
    /// Whether native UDP datagrams are supported.
    pub supports_udp_datagram: bool,
    /// Whether UDP-over-stream fallback is supported.
    pub supports_udp_stream_fallback: bool,
    /// Peer-advertised idle timeout in seconds. Zero disables idle timeout.
    pub idle_timeout_seconds: u64,
}

impl NegotiatedSettings {
    /// Returns frame reader limits derived from negotiated settings.
    pub fn frame_limits(self) -> FrameLimits {
        FrameLimits {
            max_frame_size: self.max_frame_size,
        }
    }

    /// Returns true when UDP-over-stream fallback can be used for new UDP flows.
    pub fn udp_stream_fallback_enabled(self) -> bool {
        self.supports_udp_stream_fallback && self.max_udp_flows != 0
    }
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

    /// Applies v0.1 SETTINGS defaults and rejects unsupported peer values.
    pub fn negotiated_v0_1(&self) -> ProtocolResult<NegotiatedSettings> {
        let Some(revision) = self.get(SettingKey::ProtocolRevision) else {
            return Err(ProtocolError::InvalidSettings("missing protocol revision"));
        };
        if revision != PROTOCOL_REVISION_V0_1 {
            return Err(ProtocolError::InvalidSettings(
                "unsupported protocol revision",
            ));
        }

        reject_zero_setting(self, SettingKey::MaxFrameSize, "max_frame_size")?;
        reject_zero_setting(self, SettingKey::MaxStreams, "max_streams")?;
        reject_boolean_setting(
            self,
            SettingKey::SupportsUdpDatagram,
            "supports_udp_datagram",
        )?;
        reject_boolean_setting(
            self,
            SettingKey::SupportsUdpStreamFallback,
            "supports_udp_stream_fallback",
        )?;
        reject_small_setting(
            self,
            SettingKey::MaxFrameSize,
            "max_frame_size",
            MIN_TCP_RELAY_FRAME_SIZE,
        )?;
        reject_large_setting(
            self,
            SettingKey::MaxFrameSize,
            "max_frame_size",
            MAX_FRAME_PAYLOAD_SIZE,
        )?;

        let max_frame_size = self
            .get(SettingKey::MaxFrameSize)
            .unwrap_or(DEFAULT_MAX_FRAME_SIZE);
        let max_streams = self
            .get(SettingKey::MaxStreams)
            .unwrap_or(DEFAULT_MAX_STREAMS);
        let max_udp_flows = self.get(SettingKey::MaxUdpFlows).unwrap_or(max_streams);
        if max_udp_flows > max_streams {
            return Err(ProtocolError::InvalidSettings(
                "max_udp_flows exceeds max_streams",
            ));
        }

        Ok(NegotiatedSettings {
            max_frame_size,
            max_streams,
            max_udp_flows,
            supports_udp_datagram: self.get(SettingKey::SupportsUdpDatagram).unwrap_or(0) != 0,
            supports_udp_stream_fallback: self
                .get(SettingKey::SupportsUdpStreamFallback)
                .unwrap_or(1)
                != 0,
            idle_timeout_seconds: self.get(SettingKey::IdleTimeoutSeconds).unwrap_or(0),
        })
    }
}

fn reject_zero_setting(
    settings: &Settings,
    key: SettingKey,
    name: &'static str,
) -> ProtocolResult<()> {
    if settings.get(key) == Some(0) {
        Err(ProtocolError::InvalidSettings(name))
    } else {
        Ok(())
    }
}

fn reject_boolean_setting(
    settings: &Settings,
    key: SettingKey,
    name: &'static str,
) -> ProtocolResult<()> {
    if settings.get(key).is_some_and(|value| value > 1) {
        Err(ProtocolError::InvalidSettings(name))
    } else {
        Ok(())
    }
}

fn reject_small_setting(
    settings: &Settings,
    key: SettingKey,
    name: &'static str,
    minimum: u64,
) -> ProtocolResult<()> {
    if settings.get(key).is_some_and(|value| value < minimum) {
        Err(ProtocolError::InvalidSettings(name))
    } else {
        Ok(())
    }
}

fn reject_large_setting(
    settings: &Settings,
    key: SettingKey,
    name: &'static str,
    maximum: u64,
) -> ProtocolResult<()> {
    if settings.get(key).is_some_and(|value| value > maximum) {
        Err(ProtocolError::InvalidSettings(name))
    } else {
        Ok(())
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
    fn encodes_settings_vector() {
        let mut settings = Settings::default();
        settings.set(SettingKey::MaxFrameSize, 65_536);
        settings.set(SettingKey::MaxStreams, 64);
        settings.set(SettingKey::MaxUdpFlows, 64);
        settings.set(SettingKey::SupportsUdpDatagram, 0);
        settings.set(SettingKey::SupportsUdpStreamFallback, 1);
        settings.set(SettingKey::ProtocolRevision, 1);

        let mut out = Vec::new();
        settings.encode(&mut out).unwrap();
        assert_eq!(
            out,
            [
                0x06, 0x01, 0x80, 0x01, 0x00, 0x00, 0x02, 0x40, 0x40, 0x03, 0x40, 0x40, 0x04, 0x00,
                0x05, 0x01, 0x07, 0x01
            ]
        );
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

    #[test]
    fn negotiates_v0_1_settings_with_defaults() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V0_1);

        let negotiated = settings.negotiated_v0_1().unwrap();

        assert_eq!(negotiated.max_frame_size, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(negotiated.max_streams, DEFAULT_MAX_STREAMS);
        assert_eq!(negotiated.max_udp_flows, DEFAULT_MAX_STREAMS);
        assert!(!negotiated.supports_udp_datagram);
        assert!(negotiated.supports_udp_stream_fallback);
        assert_eq!(negotiated.idle_timeout_seconds, 0);
    }

    #[test]
    fn negotiates_v0_1_settings_with_explicit_values() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V0_1);
        settings.set(SettingKey::MaxFrameSize, 4096);
        settings.set(SettingKey::MaxStreams, 8);
        settings.set(SettingKey::MaxUdpFlows, 3);
        settings.set(SettingKey::SupportsUdpDatagram, 1);
        settings.set(SettingKey::SupportsUdpStreamFallback, 0);
        settings.set(SettingKey::IdleTimeoutSeconds, 42);

        let negotiated = settings.negotiated_v0_1().unwrap();

        assert_eq!(
            negotiated.frame_limits(),
            FrameLimits {
                max_frame_size: 4096
            }
        );
        assert_eq!(negotiated.max_streams, 8);
        assert_eq!(negotiated.max_udp_flows, 3);
        assert!(negotiated.supports_udp_datagram);
        assert!(!negotiated.supports_udp_stream_fallback);
        assert!(!negotiated.udp_stream_fallback_enabled());
        assert_eq!(negotiated.idle_timeout_seconds, 42);
    }

    #[test]
    fn disables_udp_stream_fallback_without_udp_flow_capacity() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V0_1);
        settings.set(SettingKey::MaxStreams, 8);
        settings.set(SettingKey::MaxUdpFlows, 0);
        settings.set(SettingKey::SupportsUdpStreamFallback, 1);

        let negotiated = settings.negotiated_v0_1().unwrap();

        assert_eq!(negotiated.max_udp_flows, 0);
        assert!(!negotiated.udp_stream_fallback_enabled());
    }

    #[test]
    fn rejects_missing_protocol_revision() {
        assert_eq!(
            Settings::default().negotiated_v0_1(),
            Err(ProtocolError::InvalidSettings("missing protocol revision"))
        );
    }

    #[test]
    fn rejects_unsupported_protocol_revision() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);

        assert_eq!(
            settings.negotiated_v0_1(),
            Err(ProtocolError::InvalidSettings(
                "unsupported protocol revision"
            ))
        );
    }

    #[test]
    fn rejects_zero_settings_that_must_be_positive() {
        for (key, name) in [
            (SettingKey::MaxFrameSize, "max_frame_size"),
            (SettingKey::MaxStreams, "max_streams"),
        ] {
            let mut settings = Settings::default();
            settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V0_1);
            settings.set(key, 0);

            assert_eq!(
                settings.negotiated_v0_1(),
                Err(ProtocolError::InvalidSettings(name))
            );
        }
    }

    #[test]
    fn rejects_frame_size_outside_tcp_relay_bounds() {
        for value in [MIN_TCP_RELAY_FRAME_SIZE - 1, MAX_FRAME_PAYLOAD_SIZE + 1] {
            let mut settings = Settings::default();
            settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V0_1);
            settings.set(SettingKey::MaxFrameSize, value);

            assert_eq!(
                settings.negotiated_v0_1(),
                Err(ProtocolError::InvalidSettings("max_frame_size"))
            );
        }
    }

    #[test]
    fn rejects_non_boolean_support_flags() {
        for (key, name) in [
            (SettingKey::SupportsUdpDatagram, "supports_udp_datagram"),
            (
                SettingKey::SupportsUdpStreamFallback,
                "supports_udp_stream_fallback",
            ),
        ] {
            let mut settings = Settings::default();
            settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V0_1);
            settings.set(key, 2);

            assert_eq!(
                settings.negotiated_v0_1(),
                Err(ProtocolError::InvalidSettings(name))
            );
        }
    }

    #[test]
    fn rejects_udp_flow_limit_above_stream_limit() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V0_1);
        settings.set(SettingKey::MaxStreams, 8);
        settings.set(SettingKey::MaxUdpFlows, 9);

        assert_eq!(
            settings.negotiated_v0_1(),
            Err(ProtocolError::InvalidSettings(
                "max_udp_flows exceeds max_streams"
            ))
        );
    }
}
