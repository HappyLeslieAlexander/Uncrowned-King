use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::sync::watch;
use uk_auth::{AuthenticatedIdentity, Credential};
use uk_policy::PolicySet;

const INITIAL_GENERATION: u64 = 1;

#[derive(Clone)]
pub(crate) struct AccessControl {
    current: watch::Sender<Arc<AccessControlState>>,
    next_generation: Arc<AtomicU64>,
}

struct AccessControlState {
    generation: u64,
    credentials: Arc<Vec<Credential>>,
    policy_set: Arc<PolicySet>,
    auth_skew: Duration,
}

pub(crate) struct AuthenticationSnapshot {
    pub(crate) generation: u64,
    pub(crate) credentials: Arc<Vec<Credential>>,
    pub(crate) auth_skew: Duration,
}

pub(crate) struct PolicySnapshot {
    pub(crate) generation: u64,
    pub(crate) policy_set: Arc<PolicySet>,
}

impl AccessControl {
    pub(crate) fn new(
        credentials: Vec<Credential>,
        policy_set: PolicySet,
        auth_skew: Duration,
    ) -> Self {
        let state = Arc::new(AccessControlState {
            generation: INITIAL_GENERATION,
            credentials: Arc::new(credentials),
            policy_set: Arc::new(policy_set),
            auth_skew,
        });
        let (current, _) = watch::channel(state);
        Self {
            current,
            next_generation: Arc::new(AtomicU64::new(INITIAL_GENERATION + 1)),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.current.borrow().generation
    }

    pub(crate) fn authentication_snapshot(&self) -> AuthenticationSnapshot {
        let state = self.current.borrow();
        AuthenticationSnapshot {
            generation: state.generation,
            credentials: Arc::clone(&state.credentials),
            auth_skew: state.auth_skew,
        }
    }

    pub(crate) fn policy_snapshot(
        &self,
        identity: &AuthenticatedIdentity,
        now: u64,
    ) -> Option<PolicySnapshot> {
        let state = self.current.borrow();
        state.credentials.iter().find(|credential| {
            credential.key_id == identity.key_id
                && credential.policy_group == identity.policy_group
                && credential.is_active_at(now)
        })?;
        Some(PolicySnapshot {
            generation: state.generation,
            policy_set: Arc::clone(&state.policy_set),
        })
    }

    pub(crate) fn replace(
        &self,
        credentials: Vec<Credential>,
        policy_set: PolicySet,
        auth_skew: Duration,
    ) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        self.current.send_replace(Arc::new(AccessControlState {
            generation,
            credentials: Arc::new(credentials),
            policy_set: Arc::new(policy_set),
            auth_skew,
        }));
        generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(key_id: &[u8], secret: &[u8]) -> Credential {
        Credential::active(key_id.to_vec(), secret.to_vec()).unwrap()
    }

    #[test]
    fn replacement_is_visible_only_to_new_snapshots() {
        let access_control = AccessControl::new(
            vec![credential(b"old", b"0123456789abcdef0123456789abcdef")],
            PolicySet::default(),
            Duration::from_secs(30),
        );
        let old_authentication = access_control.authentication_snapshot();
        let old_identity = AuthenticatedIdentity::from(&old_authentication.credentials[0]);
        let old_policy = access_control.policy_snapshot(&old_identity, 1).unwrap();

        let generation = access_control.replace(
            vec![credential(b"new", b"fedcba9876543210fedcba9876543210")],
            PolicySet::default(),
            Duration::from_secs(60),
        );
        let new_authentication = access_control.authentication_snapshot();
        let new_identity = AuthenticatedIdentity::from(&new_authentication.credentials[0]);
        let new_policy = access_control.policy_snapshot(&new_identity, 1).unwrap();

        assert_eq!(generation, 2);
        assert_eq!(access_control.generation(), 2);
        assert_eq!(old_authentication.generation, 1);
        assert_eq!(old_authentication.credentials[0].key_id, b"old");
        assert_eq!(old_authentication.auth_skew, Duration::from_secs(30));
        assert_eq!(old_policy.generation, 1);
        assert_eq!(new_authentication.generation, 2);
        assert_eq!(new_authentication.credentials[0].key_id, b"new");
        assert_eq!(new_authentication.auth_skew, Duration::from_secs(60));
        assert_eq!(new_policy.generation, 2);
        assert!(!Arc::ptr_eq(&old_policy.policy_set, &new_policy.policy_set));
        assert!(access_control.policy_snapshot(&old_identity, 1).is_none());
    }

    #[test]
    fn disabled_or_reassigned_credentials_cannot_open_new_flows() {
        let mut active = credential(b"client", b"0123456789abcdef0123456789abcdef");
        active.policy_group = Some("default".to_owned());
        let identity = AuthenticatedIdentity::from(&active);
        let access_control =
            AccessControl::new(vec![active], PolicySet::default(), Duration::from_secs(30));
        assert!(access_control.policy_snapshot(&identity, 1).is_some());

        let mut disabled = credential(b"client", b"fedcba9876543210fedcba9876543210");
        disabled.status = uk_auth::CredentialStatus::Disabled;
        disabled.policy_group = Some("default".to_owned());
        access_control.replace(
            vec![disabled],
            PolicySet::default(),
            Duration::from_secs(30),
        );
        assert!(access_control.policy_snapshot(&identity, 1).is_none());

        let mut reassigned = credential(b"client", b"abcdef0123456789abcdef0123456789");
        reassigned.policy_group = Some("admins".to_owned());
        access_control.replace(
            vec![reassigned],
            PolicySet::default(),
            Duration::from_secs(30),
        );
        assert!(access_control.policy_snapshot(&identity, 1).is_none());
    }
}
