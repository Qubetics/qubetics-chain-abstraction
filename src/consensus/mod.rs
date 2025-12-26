use crate::types::{ConsensusMessage, ConsensusResult, SerializablePeerId};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info, warn};

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

                // SECURITY CHECK 1: Validate round parameter matches result.round
                if result.round != round {
                    return Err(anyhow::anyhow!(
                        "Consensus round mismatch: payload={} wrapper={}",
                        result.round,
                        round
                    ));
                }

                // SECURITY CHECK 2: Validate round is reasonable (not too far in future/past)
                // Allow rounds up to 1000 in the future (for network delays) and any past round
                const MAX_FUTURE_ROUND_OFFSET: u64 = 1000;
                if round > self.current_round.saturating_add(MAX_FUTURE_ROUND_OFFSET) {
                    return Err(anyhow::anyhow!(
                        "Invalid consensus round {}: too far in future (current_round={}, max_offset={})",
                        round,
                        self.current_round,
                        MAX_FUTURE_ROUND_OFFSET
                    ));
                }

                // SECURITY CHECK 3: Require that we have selected_nodes for this round
                // This ensures we participated in the round and can validate the result
                // DO NOT reconstruct from untrusted node_frequencies - this is a security vulnerability
                let selected_nodes = match self.selected_nodes_by_round.get(&round) {
                    Some(nodes) => {
                        if nodes.is_empty() {
                            return Err(anyhow::anyhow!(
                                "Selected nodes list for round {} is empty",
                                round
                            ));
                        }
                        info!(
                            "✅ [CONSENSUS] Using existing selected nodes for round {}: {} nodes",
                            round,
                            nodes.len()
                        );
                        nodes.clone()
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "Cannot validate consensus result for round {}: no selected nodes available. This node must have participated in the round to validate results.",
                            round
                        ));
                    }
                };

                // SECURITY CHECK 4: Verify final_node is actually in the selected_nodes
                let final_node_in_selected =
                    selected_nodes.iter().any(|node| *node == result.final_node);
                if !final_node_in_selected {
                    return Err(anyhow::anyhow!(
                        "Invalid consensus result for round {}: final_node {:?} is not in selected_nodes {:?}",
                        round,
                        result.final_node,
                        selected_nodes
                    ));
                }

                // SECURITY CHECK 5: If we already have a result, validate the new one before overwriting
                if let Some(existing_result) = self.consensus_results.get(&round) {
                    // Even if final_node matches, we must validate the new result is correct
                    // Don't trust - verify!
                    warn!(
                        "⚠️ [CONSENSUS] Already have consensus result for round {}: existing={:?}, received={:?}. Validating before overwriting...",
                        round, existing_result.final_node, result.final_node
                    );
                    // Continue with full validation below
                }

                // SECURITY CHECK 6: Compute expected result from our selected_nodes
                // This is the ground truth - we trust our own selected_nodes
                let expected_result = Self::calculate_consensus_result(&selected_nodes, round)?;

                // STRICT VALIDATION: Ensure consensus results match exactly
                // With aggressive VRF retries (100-500ms), all nodes should receive complete
                // VRF data before consensus calculation, so strict validation is safe.
                
                // Validate that the received result is internally consistent
                let received_final_node = Self::calculate_final_node_from_frequencies(&result.node_frequencies,round)?;
                if received_final_node != result.final_node {
                    return Err(anyhow::anyhow!(
                        "Consensus result inconsistency for round {}: final_node {:?} doesn't match calculation from node_frequencies {:?}",
                        round, result.final_node, result.node_frequencies
                    ));
                }
                
                // Strict validation: final_node must match exactly
                if expected_result.final_node != result.final_node {
                    return Err(anyhow::anyhow!(
                        "Invalid consensus result received for round {}: final_node mismatch. Expected: {:?} (total={}, frequencies={:?}). Received: {:?} (total={}, frequencies={:?})",
                        round,
                        expected_result.final_node,
                        expected_result.total_selections,
                        expected_result.node_frequencies,
                        result.final_node,
                        result.total_selections,
                        result.node_frequencies
                    ));
                }

                // Final node matches - accept the result
                // Note: total_selections and frequencies may differ slightly if nodes received
                // VRF broadcasts in different orders, but as long as final_node matches,
                // the consensus is valid
                if expected_result.total_selections != result.total_selections || expected_result.node_frequencies != result.node_frequencies {
                    info!(
                        "ℹ️ [CONSENSUS] Accepting consensus result for round {} with matching final_node {:?} but different frequencies (expected: total={}, got: total={})",
                        round, result.final_node, expected_result.total_selections, result.total_selections
                    );
                } else {
                    info!(
                        "✅ [CONSENSUS] Accepting fully validated consensus result for round {}: final_node={:?}",
                        round, result.final_node
                    );
                }

                // Consensus result accepted - store it

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
            // All nodes have the same frequency - use all unique nodes as candidates
            node_frequencies.keys().cloned().collect()
        } else {
            // Only nodes with max_frequency are candidates
            node_frequencies
                .iter()
                .filter(|(_, &freq)| freq == max_frequency)
                .map(|(node, _)| node.clone())
                .collect()
        };

        // Use cryptographic hash-based tie-breaking to prevent PeerId grinding attacks
        // Hash: SHA256(round_bytes || peer_id_bytes) - deterministic but fair per round
        candidates.sort_by(|a, b| {
            let hash_a = Self::tie_breaker_hash(round, &a.0);
            let hash_b = Self::tie_breaker_hash(round, &b.0);
            hash_a.cmp(&hash_b)
        });
        info!(
            "📋 [CONSENSUS] Candidates with max frequency {}: {:?}",
            max_frequency, candidates
        );

        let final_node = candidates[0].clone();

        if all_same_frequency {
            info!(
                "⚖️ [CONSENSUS] All nodes tied ({} each), picking by hash-based tie-breaker: {:?}",
                first_frequency.unwrap_or(0),
                final_node
            );
        } else {
            info!(
                "🏆 [CONSENSUS] Picking from freq‐{} candidates by hash-based tie-breaker: {:?}",
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

    /// Calculate the final node from node frequencies (helper for validation)
    fn calculate_final_node_from_frequencies(
        node_frequencies: &HashMap<SerializablePeerId, usize>,
        round: u64,
    ) -> Result<SerializablePeerId> {
        if node_frequencies.is_empty() {
            return Err(anyhow::anyhow!("No node frequencies available"));
        }

        let mut max_frequency = 0;
        let mut all_same_frequency = true;
        let mut first_frequency = None;

        for (_, frequency) in node_frequencies {
            if first_frequency.is_none() {
                first_frequency = Some(*frequency);
            } else if first_frequency.unwrap() != *frequency {
                all_same_frequency = false;
            }

            if *frequency > max_frequency {
                max_frequency = *frequency;
            }
        }

        let mut candidates: Vec<SerializablePeerId> = if all_same_frequency {
            node_frequencies.keys().cloned().collect()
        } else {
            node_frequencies
                .iter()
                .filter(|(_, &freq)| freq == max_frequency)
                .map(|(node, _)| node.clone())
                .collect()
        };

        // Use the same cryptographic hash-based tie-breaking as calculate_consensus_result
        candidates.sort_by(|a, b| {
            let hash_a = Self::tie_breaker_hash(round, &a.0);
            let hash_b = Self::tie_breaker_hash(round, &b.0);
            hash_a.cmp(&hash_b)
        });

        Ok(candidates[0].clone())
    }

    /// Compute a deterministic tie-breaker hash for leader selection
    /// Uses SHA256(round_bytes || peer_id_bytes) to prevent PeerId grinding attacks
    /// This ensures fairness: an attacker cannot precompute a PeerId that always wins
    /// because the hash depends on the round number, which changes each round.
    fn tie_breaker_hash(round: u64, peer_id: &libp2p::PeerId) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(round.to_be_bytes());
        hasher.update(peer_id.to_bytes());
        hasher.finalize().into()
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

        // Should select one of the nodes when all have same frequency (hash-based tie-breaker)
        assert!(
            nodes.contains(&result.final_node),
            "Selected node should be one of the candidates"
        );
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
