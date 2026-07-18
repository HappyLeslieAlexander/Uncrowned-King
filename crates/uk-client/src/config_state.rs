use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tokio::sync::watch;

use crate::config::ClientConfig;

const INITIAL_GENERATION: u64 = 1;

#[derive(Clone)]
pub(crate) struct ClientConfigState {
    current: watch::Sender<Arc<ClientConfigGeneration>>,
    next_generation: Arc<AtomicU64>,
}

struct ClientConfigGeneration {
    generation: u64,
    config: Arc<ClientConfig>,
}

#[derive(Clone)]
pub(crate) struct ClientConfigSnapshot {
    pub(crate) generation: u64,
    pub(crate) config: Arc<ClientConfig>,
}

impl ClientConfigState {
    pub(crate) fn new(config: ClientConfig) -> Self {
        let generation = Arc::new(ClientConfigGeneration {
            generation: INITIAL_GENERATION,
            config: Arc::new(config),
        });
        let (current, _) = watch::channel(generation);
        Self {
            current,
            next_generation: Arc::new(AtomicU64::new(INITIAL_GENERATION + 1)),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.current.borrow().generation
    }

    pub(crate) fn snapshot(&self) -> ClientConfigSnapshot {
        let current = self.current.borrow();
        ClientConfigSnapshot {
            generation: current.generation,
            config: Arc::clone(&current.config),
        }
    }

    pub(crate) fn replace(&self, config: ClientConfig) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        self.current.send_replace(Arc::new(ClientConfigGeneration {
            generation,
            config: Arc::new(config),
        }));
        generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(server_addr: &str, secret: &str) -> ClientConfig {
        ClientConfig {
            server_addr: server_addr.to_owned(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: "ca.pem".to_owned(),
            key_id: "client".to_owned(),
            secret: secret.to_owned(),
            handshake_timeout_seconds: None,
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: None,
            tcp_open_timeout_seconds: None,
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        }
    }

    #[test]
    fn replacement_is_visible_only_to_new_snapshots() {
        let state =
            ClientConfigState::new(config("127.0.0.1:9443", "0123456789abcdef0123456789abcdef"));
        let old = state.snapshot();

        let generation =
            state.replace(config("127.0.0.1:9444", "fedcba9876543210fedcba9876543210"));
        let new = state.snapshot();

        assert_eq!(generation, 2);
        assert_eq!(state.generation(), 2);
        assert_eq!(old.generation, 1);
        assert_eq!(old.config.server_addr, "127.0.0.1:9443");
        assert_eq!(new.generation, 2);
        assert_eq!(new.config.server_addr, "127.0.0.1:9444");
        assert!(!Arc::ptr_eq(&old.config, &new.config));
    }
}
