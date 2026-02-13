use crate::types::{KeyShare, SerializablePoint};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DKGMessage {
    ShareValidation {
        from: String,
        to: String,
        is_valid: bool,
        round: u64,
    },
    /// Broadcasted when a new node joins and needs shares
    NewNodeJoined {
        new_node_id: String,
        new_node_index: usize,
    },
    /// Sent from existing nodes to the new node with a share
    NewNodeShare {
        from: String,
        to: String,
        share: KeyShare,
        commitment: Vec<SerializablePoint>,
        new_node_index: usize, // The index calculated by existing nodes for the new node
    },
    /// Broadcasted to trigger polynomial refresh after new node joins.
    /// `participants` carries the authoritative (peer_id, index) list so all
    /// nodes use the exact same set – eliminates the gossipsub race where
    /// TriggerRefresh can arrive before NewNodeJoined on some peers.
    TriggerRefresh {
        trigger_node: String,
        participants: Vec<(String, usize)>,
    },
    /// Broadcasted when a node disconnects to notify all other nodes
    NodeDisconnected {
        disconnected_node_id: String,
        broadcaster_node_id: String,
    },
    /// Refresh shares sent from each node during proactive refresh
    // RefreshShare {
    //     from: String,
    //     shares: Vec<KeyShare>,
    //     commitments: Vec<SerializablePoint>,
    // },
    /// Individual shares are sent via P2P RPC (SendDKGShare).
    CommitmentBroadcast {
        from: String,
        commitments: Vec<SerializablePoint>,
        round: u64,
    },
    /// Refresh commitments broadcast (shares sent via P2P RPC SendRefreshShare)
    RefreshCommitmentBroadcast {
        from: String,
        commitments: Vec<SerializablePoint>,
    },
}
