use crate::types::p2p::SerializablePeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Output of a VRF evaluation containing the proof, hash, and derived value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfOutput {
    pub proof: Vec<u8>,
    pub hash: Vec<u8>,
    pub value: u64,
}

impl VrfOutput {
    pub fn new(proof: Vec<u8>, hash: Vec<u8>, value: u64) -> Self {
        Self { proof, hash, value }
    }
}

/// Result of running the VRF-based node selection across the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSelectionResult {
    pub selected_nodes: Vec<SerializablePeerId>,
    pub vrf_outputs: HashMap<SerializablePeerId, VrfOutput>,
    pub threshold: usize,
    pub total_nodes: usize,
    pub selection_round: u64,
}

impl NodeSelectionResult {
    pub fn new(
        selected_nodes: Vec<SerializablePeerId>,
        vrf_outputs: HashMap<SerializablePeerId, VrfOutput>,
        threshold: usize,
        total_nodes: usize,
        selection_round: u64,
    ) -> Self {
        Self {
            selected_nodes,
            vrf_outputs,
            threshold,
            total_nodes,
            selection_round,
        }
    }
}

/// Messages used to coordinate VRF submissions and publish the final result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VrfSelectionMessage {
    /// Node submits its VRF proof for selection.
    VrfSubmission {
        node_id: SerializablePeerId,
        vrf_output: VrfOutput,
        public_key: Vec<u8>,
        round: u64,
    },
    /// Final selection result broadcast that includes the committee decisions.
    SelectionResult {
        result: NodeSelectionResult,
        round: u64,
    },
}

/// Broadcast sent once nodes have been selected through the VRF process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfSelectedNodesBroadcast {
    pub selected_nodes: Vec<SerializablePeerId>,
    pub round: u64,
    pub selector_node_id: SerializablePeerId,
    pub timestamp: u64,
}

impl VrfSelectedNodesBroadcast {
    pub fn new(
        selected_nodes: Vec<SerializablePeerId>,
        round: u64,
        selector_node_id: SerializablePeerId,
        timestamp: u64,
    ) -> Self {
        Self {
            selected_nodes,
            round,
            selector_node_id,
            timestamp,
        }
    }
}

/// VRF round synchronization request sent between peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VrfRoundSyncRequest {
    pub from: SerializablePeerId,
    pub current_round: Option<u64>,
    pub context: String,
}

/// VRF round synchronization response including the sender's current round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VrfRoundSyncResponse {
    pub from: SerializablePeerId,
    pub current_round: Option<u64>,
    pub context: String,
}

#[cfg(test)]
mod tests {
    use super::{VrfRoundSyncRequest, VrfRoundSyncResponse};
    use crate::types::p2p::SerializablePeerId;
    use libp2p::PeerId;

    #[test]
    fn vrf_round_sync_request_serializes_and_deserializes() {
        let request = VrfRoundSyncRequest {
            from: SerializablePeerId(PeerId::random()),
            current_round: Some(7),
            context: "ctx".to_string(),
        };

        let encoded = serde_cbor::to_vec(&request).expect("request should serialize");
        let decoded: VrfRoundSyncRequest =
            serde_cbor::from_slice(&encoded).expect("request should deserialize");

        assert_eq!(decoded.from, request.from);
        assert_eq!(decoded.current_round, Some(7));
    }

    #[test]
    fn vrf_round_sync_response_serializes_and_deserializes() {
        let response = VrfRoundSyncResponse {
            from: SerializablePeerId(PeerId::random()),
            current_round: None,
            context: "ctx".to_string(),
        };

        let encoded = serde_cbor::to_vec(&response).expect("response should serialize");
        let decoded: VrfRoundSyncResponse =
            serde_cbor::from_slice(&encoded).expect("response should deserialize");

        assert_eq!(decoded.from, response.from);
        assert_eq!(decoded.current_round, None);
        assert_eq!(decoded.context, "ctx");
    }
}
