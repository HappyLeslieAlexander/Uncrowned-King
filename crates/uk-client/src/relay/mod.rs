//! Client-side SOCKS5 and UK relay.
#![allow(unused_imports, clippy::wildcard_imports)]

pub(crate) mod carrier;
pub(crate) mod context;
pub(crate) mod listener;
pub(crate) mod session_manager;
pub(crate) mod tcp;
pub(crate) mod udp;

#[cfg(test)]
mod tests;

pub(crate) use listener::{
    run_socks5_listener_on_until_shutdown, run_socks5_listener_on_until_shutdown_with_reload,
    run_socks5_listener_until_shutdown, run_socks5_listener_until_shutdown_with_reload,
};
