use crate::types::SerializablePoint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DKGMessage {
    ShareValidation {
        from: String,
        to: String,
        is_valid: bool,
        round: u64,
    },
    /// Broadcasted when a node disconnects to notify all other nodes
    NodeDisconnected {
        disconnected_node_id: String,
        broadcaster_node_id: String,
    },
    /// Individual shares are sent via P2P RPC (SendDKGShare).
    CommitmentBroadcast {
        from: String,
        commitments: Vec<SerializablePoint>,
        round: u64,
    },
}
