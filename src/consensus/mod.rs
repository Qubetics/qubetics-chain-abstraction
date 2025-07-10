use crate::types::p2p::SerializablePeerId;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

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

#[derive(Clone)]
pub struct ConsensusNode {
    current_round: u64,
    selected_nodes_by_round: HashMap<u64, Vec<SerializablePeerId>>,
    consensus_results: HashMap<u64, ConsensusResult>,
}

impl ConsensusNode {
    pub fn new() -> Self {
        Self {
            current_round: 0,
            selected_nodes_by_round: HashMap::new(),
            consensus_results: HashMap::new(),
        }
    }

    /// Add selected nodes for a specific round
    pub fn add_selected_nodes(&mut self, round: u64, selected_nodes: Vec<SerializablePeerId>) {
        info!(
            "📋 [CONSENSUS] Adding {} selected nodes for round {}",
            selected_nodes.len(),
            round
        );
        self.selected_nodes_by_round.insert(round, selected_nodes);
    }

    /// Start consensus for a specific round
    pub fn start_consensus(&mut self, round: u64) -> Result<ConsensusResult> {
        info!("🎯 [CONSENSUS] Starting consensus for round {}", round);

        let selected_nodes = self
            .selected_nodes_by_round
            .get(&round)
            .ok_or_else(|| anyhow::anyhow!("No selected nodes found for round {}", round))?;

        if selected_nodes.is_empty() {
            return Err(anyhow::anyhow!("No selected nodes available for consensus"));
        }

        // Count frequency of each node
        let mut node_frequencies: HashMap<SerializablePeerId, usize> = HashMap::new();

        for node in selected_nodes {
            *node_frequencies.entry(node.clone()).or_insert(0) += 1;
        }

        info!(
            "📊 [CONSENSUS] Node frequencies for round {}: {:?}",
            round, node_frequencies
        );

        // Find the most frequently selected node
        let mut max_frequency = 0;
        let mut most_frequent_node = None;
        let mut all_same_frequency = true;
        let mut first_frequency = None;

        for (node, frequency) in &node_frequencies {
            if first_frequency.is_none() {
                first_frequency = Some(*frequency);
            } else if first_frequency.unwrap() != *frequency {
                all_same_frequency = false;
            }

            if *frequency > max_frequency {
                max_frequency = *frequency;
                most_frequent_node = Some(node.clone());
            }
        }

        let final_node = if all_same_frequency {
            // If all nodes appear the same number of times, select the first node
            let first_node = selected_nodes.first().unwrap().clone();
            info!(
                "⚖️ [CONSENSUS] All nodes have same frequency ({}), selecting first node: {:?}",
                first_frequency.unwrap_or(0),
                first_node
            );
            first_node
        } else {
            // Select the most frequently selected node
            let final_node = most_frequent_node.unwrap();
            info!(
                "🏆 [CONSENSUS] Most frequently selected node: {:?} ({} times)",
                final_node, max_frequency
            );
            final_node
        };

        let result = ConsensusResult {
            final_node,
            round,
            node_frequencies,
            total_selections: selected_nodes.len(),
        };

        self.consensus_results.insert(round, result.clone());
        self.current_round = round;

        info!(
            "✅ [CONSENSUS] Consensus completed for round {}: final node = {:?}",
            round, result.final_node
        );

        Ok(result)
    }

    /// Get consensus result for a specific round
    pub fn get_consensus_result(&self, round: u64) -> Option<&ConsensusResult> {
        self.consensus_results.get(&round)
    }

    /// Get the current round
    pub fn get_current_round(&self) -> u64 {
        self.current_round
    }

    /// Advance to the next round
    pub fn advance_round(&mut self) {
        self.current_round += 1;
        debug!("🔄 [CONSENSUS] Advanced to round {}", self.current_round);
    }

    /// Handle consensus messages
    pub async fn handle_message(&mut self, msg: ConsensusMessage) -> Result<()> {
        match msg {
            ConsensusMessage::FinalNodeResult { result, round } => {
                info!(
                    "📥 [CONSENSUS] Received final node result for round {}: {:?}",
                    round, result.final_node
                );
                self.consensus_results.insert(round, result);
            }
        }
        Ok(())
    }

    /// Check if this node is the final selected node for a round
    pub fn is_final_node(&self, round: u64, node_id: &SerializablePeerId) -> bool {
        if let Some(result) = self.consensus_results.get(&round) {
            result.final_node == *node_id
        } else {
            false
        }
    }

    /// Get all selected nodes for a round
    pub fn get_selected_nodes_for_round(&self, round: u64) -> Option<&Vec<SerializablePeerId>> {
        self.selected_nodes_by_round.get(&round)
    }

    /// Clear data for a specific round
    pub fn clear_round_data(&mut self, round: u64) {
        self.selected_nodes_by_round.remove(&round);
        self.consensus_results.remove(&round);
        debug!("🗑️ [CONSENSUS] Cleared data for round {}", round);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn test_consensus_most_frequent_node() {
        let mut consensus = ConsensusNode::new();

        // Create test nodes
        let nodes: Vec<SerializablePeerId> = (0..3)
            .map(|_| SerializablePeerId(libp2p::PeerId::from(Keypair::generate_ed25519().public())))
            .collect();

        // Add selected nodes where node 0 appears most frequently
        let selected_nodes = vec![
            nodes[0].clone(), // appears 3 times
            nodes[0].clone(),
            nodes[0].clone(),
            nodes[1].clone(), // appears 1 time
            nodes[2].clone(), // appears 1 time
        ];

        consensus.add_selected_nodes(1, selected_nodes);
        let result = consensus.start_consensus(1).unwrap();

        assert_eq!(result.final_node, nodes[0]);
        assert_eq!(result.node_frequencies.get(&nodes[0]), Some(&3));
        assert_eq!(result.node_frequencies.get(&nodes[1]), Some(&1));
        assert_eq!(result.node_frequencies.get(&nodes[2]), Some(&1));
    }

    #[test]
    fn test_consensus_same_frequency() {
        let mut consensus = ConsensusNode::new();

        // Create test nodes
        let nodes: Vec<SerializablePeerId> = (0..3)
            .map(|_| SerializablePeerId(libp2p::PeerId::from(Keypair::generate_ed25519().public())))
            .collect();

        // Add selected nodes where each appears once
        let selected_nodes = vec![nodes[0].clone(), nodes[1].clone(), nodes[2].clone()];

        consensus.add_selected_nodes(1, selected_nodes);
        let result = consensus.start_consensus(1).unwrap();

        // Should select the first node when all have same frequency
        assert_eq!(result.final_node, nodes[0]);
        assert_eq!(result.node_frequencies.get(&nodes[0]), Some(&1));
        assert_eq!(result.node_frequencies.get(&nodes[1]), Some(&1));
        assert_eq!(result.node_frequencies.get(&nodes[2]), Some(&1));
    }

    #[test]
    fn test_consensus_no_nodes() {
        let mut consensus = ConsensusNode::new();
        consensus.add_selected_nodes(1, vec![]);

        let result = consensus.start_consensus(1);
        assert!(result.is_err());
    }
}
