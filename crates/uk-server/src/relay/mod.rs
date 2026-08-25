//! Server-side UK TCP and UDP relay.
#![allow(unused_imports, clippy::wildcard_imports)]

pub(crate) mod context;
pub(crate) mod dialer;
pub(crate) mod session;
pub(crate) mod tasks;
pub(crate) mod tcp;
pub(crate) mod udp;

#[cfg(test)]
mod tests;

pub(crate) use context::{RelayLimitConfig, RelayLimits, ServerCarrier};
pub(crate) use session::relay_session;
