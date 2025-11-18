use crate::types::p2p::SerializablePeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// VRF output containing proof and hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfOutput {
    pub proof: Vec<u8>,
    pub hash: Vec<u8>,
    pub value: u64,
}

/// VRF-based node selection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSelectionResult {
    pub selected_nodes: Vec<SerializablePeerId>,
    pub vrf_outputs: HashMap<SerializablePeerId, VrfOutput>,
    pub threshold: usize,
    pub total_nodes: usize,
    pub selection_round: u64,
}

/// VRF node selection message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VrfSelectionMessage {
    /// Node submits its VRF proof for selection
    VrfSubmission {
        node_id: SerializablePeerId,
        vrf_output: VrfOutput,
        public_key: Vec<u8>,
        round: u64,
    },
    /// Final selection result broadcast
    SelectionResult {
        result: NodeSelectionResult,
        round: u64,
    },
}

/// Broadcast message for VRF-selected nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfSelectedNodesBroadcast {
    pub selected_nodes: Vec<SerializablePeerId>,
    pub round: u64,
    pub selector_node_id: SerializablePeerId,
    pub timestamp: u64,
}
