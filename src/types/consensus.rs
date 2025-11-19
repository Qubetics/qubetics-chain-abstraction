use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::p2p::SerializablePeerId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub final_node: SerializablePeerId,
    pub round: u64,
    pub node_frequencies: HashMap<SerializablePeerId, usize>,
    pub total_selections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// Broadcast the final consensus result
    FinalNodeResult { result: ConsensusResult, round: u64 },
}

