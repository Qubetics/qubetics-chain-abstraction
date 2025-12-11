use crate::types::{ConsensusMessage, ConsensusResult, SerializablePeerId};
use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, info};

pub mod db_consensus;
pub use db_consensus::DatabaseConsensusNode;

#[derive(Clone)]
pub struct ConsensusNode {
    current_round: u64,
    selected_nodes_by_round: HashMap<u64, Vec<SerializablePeerId>>,
    consensus_results: HashMap<u64, ConsensusResult>,
}

impl Default for ConsensusNode {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn start_consensus(&mut self, round: u64) -> Result<ConsensusResult> {
        info!("🎯 [CONSENSUS] Starting consensus for round {}", round);

        let selected_nodes = self
            .selected_nodes_by_round
            .get(&round)
            .ok_or_else(|| anyhow::anyhow!("No selected nodes found for round {}", round))?;

        let result = Self::calculate_consensus_result(selected_nodes, round)?;

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
                if result.round != round {
                    return Err(anyhow::anyhow!(
                        "Consensus round mismatch: payload={} wrapper={}",
                        result.round,
                        round
                    ));
                }

                // Get or reconstruct selected nodes for validation
                let selected_nodes = if let Some(nodes) = self.selected_nodes_by_round.get(&round) {
                    // We have the selected nodes - use them for validation
                    info!(
                        "✅ [CONSENSUS] Using existing selected nodes for round {}: {} nodes",
                        round,
                        nodes.len()
                    );
                    nodes.clone()
                } else {
                    // We don't have selected nodes (maybe we missed VRF broadcasts)
                    // Reconstruct them from the consensus result's node_frequencies
                    info!(
                        "⚠️ [CONSENSUS] No selected nodes recorded for round {}, reconstructing from consensus result node_frequencies: {:?}",
                        round,
                        result.node_frequencies
                    );
                    
                    if result.node_frequencies.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Cannot reconstruct selected nodes for round {}: node_frequencies is empty in consensus result",
                            round
                        ));
                    }
                    
                    let mut reconstructed_nodes = Vec::new();
                    for (node, frequency) in &result.node_frequencies {
                        info!(
                            "🔧 [CONSENSUS] Reconstructing: adding node {:?} {} times",
                            node, frequency
                        );
                        // Add each node 'frequency' times to match the original selection
                        for _ in 0..*frequency {
                            reconstructed_nodes.push(node.clone());
                        }
                    }
                    
                    info!(
                        "✅ [CONSENSUS] Reconstructed {} selected nodes for round {}",
                        reconstructed_nodes.len(),
                        round
                    );
                    
                    if reconstructed_nodes.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Reconstruction failed for round {}: reconstructed list is empty",
                            round
                        ));
                    }
                    
                    // Store the reconstructed nodes for future reference
                    self.selected_nodes_by_round.insert(round, reconstructed_nodes.clone());
                    reconstructed_nodes
                };

                let expected_result = Self::calculate_consensus_result(&selected_nodes, round)?;

                if expected_result != result {
                    return Err(anyhow::anyhow!(
                        "Invalid consensus result received for round {}: expected {:?}, got {:?}",
                        round,
                        expected_result.final_node,
                        result.final_node
                    ));
                }

                self.consensus_results.insert(round, result);
                self.current_round = self.current_round.max(round);
            }
        }
        Ok(())
    }

    fn calculate_consensus_result(
        selected_nodes: &[SerializablePeerId],
        round: u64,
    ) -> Result<ConsensusResult> {
        if selected_nodes.is_empty() {
            return Err(anyhow::anyhow!("No selected nodes available for consensus"));
        }

        let mut node_frequencies: HashMap<SerializablePeerId, usize> = HashMap::new();

        for node in selected_nodes {
            *node_frequencies.entry(node.clone()).or_insert(0) += 1;
        }

        info!(
            "📊 [CONSENSUS] Node frequencies for round {}: {:?}",
            round, node_frequencies
        );

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

        info!(
            "🔍 [CONSENSUS] Most frequent node: {:?} with frequency {} and all same or not {}",
            most_frequent_node, max_frequency, all_same_frequency
        );

        let mut candidates: Vec<SerializablePeerId> = if all_same_frequency {
            selected_nodes.to_vec()
        } else {
            node_frequencies
                .iter()
                .filter(|(_, &freq)| freq == max_frequency)
                .map(|(node, _)| node.clone())
                .collect()
        };

        candidates.sort_by(|a, b| a.0.to_bytes().cmp(&b.0.to_bytes()));
        info!(
            "📋 [CONSENSUS] Candidates with max frequency {}: {:?}",
            max_frequency, candidates
        );

        let final_node = candidates[0].clone();

        if all_same_frequency {
            info!(
                "⚖️ [CONSENSUS] All nodes tied ({} each), picking lexicographically first: {:?}",
                first_frequency.unwrap_or(0),
                final_node
            );
        } else {
            info!(
                "🏆 [CONSENSUS] Picking from freq‐{} candidates, lexicographically first: {:?}",
                max_frequency, final_node
            );
        }

        Ok(ConsensusResult {
            final_node,
            round,
            node_frequencies,
            total_selections: selected_nodes.len(),
        })
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
    use crate::types::ConsensusMessage;
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

    #[tokio::test]
    async fn test_handle_message_validates_consensus_result() {
        let round = 1;

        let nodes: Vec<SerializablePeerId> = (0..3)
            .map(|_| SerializablePeerId(libp2p::PeerId::from(Keypair::generate_ed25519().public())))
            .collect();

        let mut sender = ConsensusNode::new();
        sender.add_selected_nodes(round, nodes.clone());
        let result = sender
            .start_consensus(round)
            .expect("consensus should succeed");

        let mut receiver = ConsensusNode::new();
        receiver.add_selected_nodes(round, nodes.clone());

        receiver
            .handle_message(ConsensusMessage::FinalNodeResult {
                result: result.clone(),
                round,
            })
            .await
            .expect("valid consensus message should be accepted");

        assert_eq!(receiver.get_consensus_result(round), Some(&result));
    }

    #[tokio::test]
    async fn test_handle_message_rejects_tampered_result() {
        let round = 2;
        let nodes: Vec<SerializablePeerId> = (0..3)
            .map(|_| SerializablePeerId(libp2p::PeerId::from(Keypair::generate_ed25519().public())))
            .collect();

        let mut sender = ConsensusNode::new();
        sender.add_selected_nodes(round, nodes.clone());
        let mut result = sender
            .start_consensus(round)
            .expect("consensus should succeed");

        // Tamper with the final node to simulate spoofed data
        result.final_node = nodes[1].clone();

        let mut receiver = ConsensusNode::new();
        receiver.add_selected_nodes(round, nodes.clone());

        let err = receiver
            .handle_message(ConsensusMessage::FinalNodeResult { result, round })
            .await
            .expect_err("tampered consensus result should be rejected");

        assert!(err.to_string().contains("Invalid consensus result"));
        assert!(receiver.get_consensus_result(round).is_none());
    }
}
