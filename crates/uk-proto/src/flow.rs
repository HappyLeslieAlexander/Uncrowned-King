//! Flow id allocation helpers.

use crate::varint::MAX_VARINT;

/// First client-initiated flow id.
pub const FIRST_CLIENT_FLOW_ID: u64 = 1;

/// Flow id step for one peer's initiated flows.
pub const FLOW_ID_STEP: u64 = 2;

/// Returns true when `flow_id` is a valid client-initiated flow id.
pub const fn is_client_initiated_flow_id(flow_id: u64) -> bool {
    flow_id != 0 && flow_id <= MAX_VARINT && flow_id % 2 == 1
}

/// Returns true when `flow_id` is a valid server-initiated flow id.
pub const fn is_server_initiated_flow_id(flow_id: u64) -> bool {
    flow_id != 0 && flow_id <= MAX_VARINT && flow_id % 2 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_client_initiated_flow_ids() {
        assert!(is_client_initiated_flow_id(1));
        assert!(is_client_initiated_flow_id(3));
        assert!(is_client_initiated_flow_id(MAX_VARINT));
        assert!(!is_client_initiated_flow_id(0));
        assert!(!is_client_initiated_flow_id(2));
        assert!(!is_client_initiated_flow_id(MAX_VARINT + 2));
    }

    #[test]
    fn classifies_server_initiated_flow_ids() {
        assert!(is_server_initiated_flow_id(2));
        assert!(is_server_initiated_flow_id(4));
        assert!(is_server_initiated_flow_id(MAX_VARINT - 1));
        assert!(!is_server_initiated_flow_id(0));
        assert!(!is_server_initiated_flow_id(1));
        assert!(!is_server_initiated_flow_id(MAX_VARINT + 1));
    }
}
