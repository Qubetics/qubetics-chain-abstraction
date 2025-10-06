use crate::types::p2p::SerializablePeerId;
use anyhow::Result;
use ecvrf::{keygen, prove, verify, VrfPk, VrfProof, VrfSk};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use tracing::{debug, info};

use crate::types::ChannelMessage;

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

/// VRF-based node selector using ecvrf
#[derive(Debug, Clone)]
pub struct VrfNodeSelector {
    vrf_secret_key: VrfSk,
    vrf_public_key: VrfPk,
    node_id: PeerId,
    selection_round: u64,
    submissions: HashMap<u64, HashMap<PeerId, VrfOutput>>,
    results: HashMap<u64, NodeSelectionResult>,
    // Store received VRF selected nodes broadcasts from other nodes
    received_selections: HashMap<u64, HashMap<SerializablePeerId, VrfSelectedNodesBroadcast>>,
}

/// Independent VRF Service for chain-agnostic node selection
#[derive(Clone)]
pub struct VrfService {
    selector: Arc<RwLock<VrfNodeSelector>>,
    message_tx: mpsc::Sender<ChannelMessage>,
    node_id: PeerId,
    current_round: Arc<RwLock<u64>>,
}

impl VrfService {
    /// Create a new VRF service
    pub fn new(node_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        let selector = VrfNodeSelector::new(node_id);
        
        Self {
            selector: Arc::new(RwLock::new(selector)),
            message_tx,
            node_id,
            current_round: Arc::new(RwLock::new(0)),
        }
    }

    /// Perform VRF node selection for any chain operation
    pub async fn perform_node_selection(
        &self,
        available_nodes: &[PeerId],
        threshold: usize,
        round: u64,
        operation_type: &str,
    ) -> Result<NodeSelectionResult> {
        info!(
            "🎯 [VRF] Starting {} operation node selection for round {} with {} available nodes",
            operation_type, round, available_nodes.len()
        );

        let mut selector = self.selector.write().await;
        let selection_result = selector.select_mpc_nodes(available_nodes, threshold, round);
        info!("🧐 Selection result: {:?}", selection_result);
        
        info!("⏳ Waiting 3 seconds before broadcasting selection...");
        tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

        info!(
            "🎯 [VRF] Node {} selected {} nodes for {} operation round {}: {:?}",
            self.node_id,
            selection_result.selected_nodes.len(),
            operation_type,
            round,
            selection_result.selected_nodes
        );

        // Broadcast the VRF-selected nodes to all peers
        if let Some(broadcast_msg) = selector.create_selected_nodes_broadcast(round) {
            let broadcast_data = serde_json::to_vec(
                &crate::types::GossipsubMessage::VrfSelectedNodes(broadcast_msg),
            )?;
            
            self.message_tx.send(ChannelMessage::Broadcast {
                topic: "vrf-selection".to_string(),
                data: broadcast_data,
            }).await?;
            
            info!(
                "📤 [VRF] Node {} broadcasted VRF-selected nodes for {} operation round {}",
                self.node_id, operation_type, round
            );
        }

        Ok(selection_result)
    }

    /// Get all selected nodes for a round
    pub async fn get_all_selected_nodes_for_round(&self, round: u64) -> Vec<SerializablePeerId> {
        let selector = self.selector.read().await;
        selector.get_all_selected_nodes_for_round(round)
    }

    /// Handle VRF broadcast from other nodes
    pub async fn handle_vrf_broadcast(&self, broadcast: VrfSelectedNodesBroadcast, total_nodes: usize) {
        let mut selector = self.selector.write().await;
        let round = broadcast.round;
        
        selector.handle_selected_nodes_broadcast(broadcast, total_nodes);
        
        // Check if consensus can be started
        let min_selections = total_nodes;
        if selector.can_start_consensus(round, min_selections) { ////////////////////
            info!(
                "🎯 [VRF] Enough selections collected for round {}, consensus can be triggered",
                round
            );
        }
    }

    /// Check if consensus can be started for a round
    pub async fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        let selector = self.selector.read().await;
        selector.can_start_consensus(round, min_selections)
    }

    /// Get the next round number and increment it
    pub async fn get_next_round(&self) -> u64 {
        let mut current = self.current_round.write().await;
        let round = *current;
        *current += 1;
        round
    }

    /// Get current round without incrementing
    pub async fn get_current_round(&self) -> u64 {
        let current = self.current_round.read().await;
        *current
    }

    /// Set current round (used for network synchronization)
    pub async fn set_current_round(&mut self, round: u64) {
        let mut current = self.current_round.write().await;
        *current = round;
        info!("🔄 [VRF] Node {} set current round to: {}", self.node_id, round);
    }

    /// Get VRF public key
    pub async fn get_public_key(&self) -> Vec<u8> {
        let selector = self.selector.read().await;
        selector.get_public_key()
    }

    /// Get VRF public key as hex
    pub async fn get_public_key_hex(&self) -> String {
        let selector = self.selector.read().await;
        selector.get_public_key_hex()
    }

    /// Handle VRF messages
    pub async fn handle_message(&self, msg: VrfSelectionMessage) -> Result<()> {
        let mut selector = self.selector.write().await;
        selector.handle_message(msg).await
    }

    /// Get all selected nodes with frequencies for consensus
    pub async fn get_all_selected_nodes_with_frequencies(&self, round: u64) -> Vec<SerializablePeerId> {
        let selector = self.selector.read().await;
        selector.get_all_selected_nodes_with_frequencies(round)
    }

    /// Get selection result for a specific round
    pub async fn get_selection_result(&self, round: u64) -> Option<NodeSelectionResult> {
        let selector = self.selector.read().await;
        selector.get_selection_result(round).cloned()
    }
}

impl VrfNodeSelector {
    pub fn new(node_id: PeerId) -> Self {
        // Generate VRF key pair
        let (vrf_secret_key, vrf_public_key) = keygen();

        Self {
            vrf_secret_key,
            vrf_public_key,
            node_id,
            selection_round: 0,
            submissions: HashMap::new(),
            results: HashMap::new(),
            received_selections: HashMap::new(),
        }
    }

    /// Generate VRF proof for a given input using ecvrf
    pub fn generate_vrf_proof(&self, input: &[u8]) -> VrfOutput {
        // Generate VRF proof using ecvrf
        let (hash, proof) = prove(input, &self.vrf_secret_key);

        // Extract a u64 value from the hash for selection
        let value = if hash.len() >= 8 {
            u64::from_le_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ])
        } else {
            0
        };

        VrfOutput {
            proof: proof.to_bytes().to_vec(),
            hash: hash.to_vec(),
            value,
        }
    }

    /// Verify VRF proof from another node using ecvrf
    pub fn verify_vrf_proof(
        &self,
        node_public_key: &[u8],
        input: &[u8],
        output: &VrfOutput,
    ) -> bool {
        // Deserialize the public key
        let pubkey = match VrfPk::from_bytes(node_public_key.try_into().unwrap_or(&[0; 32])) {
            Ok(pk) => pk,
            Err(_) => {
                debug!("Failed to deserialize public key");
                return false;
            }
        };

        // Deserialize the proof
        let proof = match VrfProof::from_bytes(&output.proof.clone().try_into().unwrap_or([0; 96]))
        {
            Ok(p) => p,
            Err(_) => {
                debug!("Failed to deserialize VRF proof");
                return false;
            }
        };

        // Verify the proof
        let hash: [u8; 32] = output.hash.clone().try_into().unwrap_or([0; 32]);
        verify(input, &pubkey, &hash, &proof)
    }

    /// Generate VRF proof for node selection
    pub fn generate_selection_proof(&self, round: u64, available_nodes: &[PeerId]) -> VrfOutput {
        let mut input = Vec::new();
        input.extend_from_slice(&round.to_le_bytes());
        input.extend_from_slice(&self.node_id.to_bytes());

        // Include all available nodes in the input for deterministic selection
        for node in available_nodes {
            input.extend_from_slice(&node.to_bytes());
        }

        self.generate_vrf_proof(&input)
    }

    /// Select MPC nodes using VRF
    pub fn select_mpc_nodes(
        &mut self,
        available_nodes: &[PeerId],
        threshold: usize,
        round: u64,
    ) -> NodeSelectionResult {
        info!("Starting VRF-based MPC node selection for round {}", round);

        // Generate VRF proof for this node
        let vrf_output = self.generate_selection_proof(round, available_nodes);

        // Simulate collecting VRF submissions from all nodes
        let mut all_submissions = HashMap::new();
        for node in available_nodes {
            // In a real implementation, you would receive actual VRF proofs from other nodes
            // For now, we'll simulate by generating proofs for all nodes
            let simulated_proof = self.generate_selection_proof(round, available_nodes);
            all_submissions.insert(SerializablePeerId(*node), simulated_proof);
        }

        // Add our own submission
        all_submissions.insert(SerializablePeerId(self.node_id), vrf_output.clone());

        // Sort nodes by VRF values and select the top nodes
        let mut node_vrf_pairs: Vec<(SerializablePeerId, u64)> = all_submissions
            .iter()
            .map(|(node_id, output)| (node_id.clone(), output.value))
            .collect();

        node_vrf_pairs.sort_by(|a, b| a.1.cmp(&b.1));

        // Select the top nodes based on VRF values
        let selected_nodes: Vec<SerializablePeerId> = node_vrf_pairs
            .into_iter()
            .take(threshold)
            .map(|(node_id, _)| node_id)
            .collect();

        info!("🧐 Selected nodes: {:?}", selected_nodes);

        let result = NodeSelectionResult {
            selected_nodes: selected_nodes.clone(),
            vrf_outputs: all_submissions,
            threshold,
            total_nodes: available_nodes.len(),
            selection_round: round,
        };

        self.results.insert(round, result.clone());
        self.selection_round = round;

        result
    }

    /// Check if this node is selected for MPC in the current round
    pub fn is_selected(&self, round: u64) -> bool {
        if let Some(result) = self.results.get(&round) {
            result
                .selected_nodes
                .iter()
                .any(|node| node.0 == self.node_id)
        } else {
            false
        }
    }

    /// Get the current selection result
    pub fn get_selection_result(&self, round: u64) -> Option<&NodeSelectionResult> {
        self.results.get(&round)
    }

    /// Get VRF public key for verification
    pub fn get_public_key(&self) -> Vec<u8> {
        self.vrf_public_key.to_bytes().to_vec()
    }

    /// Get VRF public key as hex string
    pub fn get_public_key_hex(&self) -> String {
        hex::encode(self.vrf_public_key.to_bytes())
    }

    /// Get VRF secret key (for testing purposes)
    pub fn get_secret_key(&self) -> Vec<u8> {
        self.vrf_secret_key.to_bytes().to_vec()
    }

    /// Get VRF secret key as hex string
    pub fn get_secret_key_hex(&self) -> String {
        hex::encode(self.vrf_secret_key.to_bytes())
    }

    /// Handle incoming VRF selection messages
    pub async fn handle_message(&mut self, msg: VrfSelectionMessage) -> Result<()> {
        match msg {
            VrfSelectionMessage::VrfSubmission {
                node_id,
                vrf_output,
                round,
            } => {
                self.handle_vrf_submission(node_id.0, vrf_output, round)
                    .await?;
            }
            VrfSelectionMessage::SelectionResult { result, round } => {
                self.handle_selection_result(result, round).await?;
            }
        }
        Ok(())
    }

    async fn handle_vrf_submission(
        &mut self,
        node_id: PeerId,
        vrf_output: VrfOutput,
        round: u64,
    ) -> Result<()> {
        debug!(
            "Received VRF submission from node {} for round {}",
            node_id, round
        );

        self.submissions
            .entry(round)
            .or_insert_with(HashMap::new)
            .insert(node_id, vrf_output);

        Ok(())
    }

    async fn handle_selection_result(
        &mut self,
        result: NodeSelectionResult,
        round: u64,
    ) -> Result<()> {
        info!(
            "Received selection result for round {}: {} nodes selected",
            round,
            result.selected_nodes.len()
        );

        self.results.insert(round, result);

        if self.is_selected(round) {
            info!("This node is selected for MPC in round {}", round);
        } else {
            debug!("This node is not selected for MPC in round {}", round);
        }

        Ok(())
    }

    /// Get the current selection round
    pub fn get_current_round(&self) -> u64 {
        self.selection_round
    }

    /// Advance to the next selection round
    pub fn advance_round(&mut self) {
        self.selection_round += 1;
    }

    /// Create a broadcast message for VRF-selected nodes
    pub fn create_selected_nodes_broadcast(&self, round: u64) -> Option<VrfSelectedNodesBroadcast> {
        if let Some(result) = self.results.get(&round) {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            Some(VrfSelectedNodesBroadcast {
                selected_nodes: result.selected_nodes.clone(),
                round,
                selector_node_id: SerializablePeerId(self.node_id),
                timestamp,
            })
        } else {
            None
        }
    }

    /// Handle received VRF selected nodes broadcast from another node
    pub fn handle_selected_nodes_broadcast(&mut self, broadcast: VrfSelectedNodesBroadcast, total_nodes: usize) {
        info!(
            "📥 [VRF] Received VRF selected nodes broadcast from node {} for round {}: {} nodes selected",
            broadcast.selector_node_id.0,
            broadcast.round,
            broadcast.selected_nodes.len()
        );

        let round = broadcast.round;
        self.received_selections
            .entry(round)
            .or_insert_with(HashMap::new)
            .insert(broadcast.selector_node_id.clone(), broadcast);

        // Log the current aggregated state after receiving this broadcast
        let all_selected = self.get_all_selected_nodes_for_round(round);
        info!("All selected nodes for round {}: {:?}", round, all_selected);
        info!(
            "🔄 [VRF] Updating aggregated selections for round {}...",
            round
        );

        // Check if we have enough selections to start consensus
        let min_selections = total_nodes; // Minimum 4 selections to start consensus
        if self.can_start_consensus(round, min_selections) {
            info!(
                "🎯 [VRF] Enough selections collected for round {}, consensus can be started",
                round
            );
        }
    }

    /// Get all received VRF selections for a specific round
    pub fn get_received_selections_for_round(&self, round: u64) -> Vec<&VrfSelectedNodesBroadcast> {
        self.received_selections
            .get(&round)
            .map(|selections| selections.values().collect())
            .unwrap_or_default()
    }

    /// Get all unique selected nodes from all received broadcasts for a round
    pub fn get_all_selected_nodes_for_round(&self, round: u64) -> Vec<SerializablePeerId> {
        let mut all_selected = std::collections::HashSet::new();
        let mut own_selections = Vec::new();
        let mut received_selections = Vec::new();

        // Add our own selection if available
        if let Some(result) = self.results.get(&round) {
            info!(
                "🎯 [VRF] Our own selections for round {}: {:?}",
                round, result.selected_nodes
            );
            for node in &result.selected_nodes {
                all_selected.insert(node.clone());
                own_selections.push(node.clone());
            }
        } else {
            info!("⚠️ [VRF] No own selections found for round {} - this may be due to UTXO unavailability", round);
        }

        // Add selections from other nodes
        if let Some(selections) = self.received_selections.get(&round) {
            info!(
                "📥 [VRF] Received {} broadcasts for round {}",
                selections.len(),
                round
            );

            for (selector_id, broadcast) in selections.iter() {
                info!(
                    "📋 [VRF] From node {}: selected {} nodes: {:?}",
                    selector_id.0,
                    broadcast.selected_nodes.len(),
                    broadcast.selected_nodes
                );

                for node in &broadcast.selected_nodes {
                    all_selected.insert(node.clone());
                    received_selections.push(node.clone());
                }
            }
        } else {
            info!("⚠️ [VRF] No received selections found for round {}", round);
        }

        let final_selected: Vec<SerializablePeerId> = all_selected.into_iter().collect();

        info!(
            "🎉 [VRF] Final aggregated selections for round {}: {} unique nodes",
            round,
            final_selected.len()
        );
        info!(
            "📊 [VRF] Own selections: {}, Received selections: {}, Total unique: {}",
            own_selections.len(),
            received_selections.len(),
            final_selected.len()
        );
        info!("📋 [VRF] All unique selected nodes: {:?}", final_selected);

        final_selected
    }

    /// Get all selected nodes with their frequencies for consensus
    pub fn get_all_selected_nodes_with_frequencies(&self, round: u64) -> Vec<SerializablePeerId> {
        let mut all_selected = Vec::new();

        // Add our own selection if available
        if let Some(result) = self.results.get(&round) {
            for node in &result.selected_nodes {
                all_selected.push(node.clone());
            }
        }

        // Add selections from other nodes
        if let Some(selections) = self.received_selections.get(&round) {
            for (_selector_id, broadcast) in selections.iter() {
                for node in &broadcast.selected_nodes {
                    all_selected.push(node.clone());
                }
            }
        }

        info!(
            "📊 [VRF] Total selected nodes for consensus round {}: {} (with frequencies)",
            round,
            all_selected.len()
        );

        all_selected
    }

    /// Check if we have enough selections to start consensus
    pub fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        let own_selection = self.results.get(&round).is_some();
        let received_count = self
            .received_selections
            .get(&round)
            .map(|selections| selections.len())
            .unwrap_or(0);

        let total_selections = if own_selection {
            received_count + 1
        } else {
            received_count
        };

        info!(
            "🔍 [VRF] Consensus readiness check for round {}: own={}, received={}, total={}, min_required={}",
            round, own_selection, received_count, total_selections, min_selections
        );

        total_selections >= min_selections
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn test_vrf_proof_generation() {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let selector = VrfNodeSelector::new(node_id);

        let input = b"test input";
        let output = selector.generate_vrf_proof(input);

        assert!(!output.proof.is_empty());
        assert!(!output.hash.is_empty());
        assert!(output.value > 0);

    }

    #[test]
    fn test_vrf_verification() {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let selector = VrfNodeSelector::new(node_id);

        let input = b"test verification input";
        let output = selector.generate_vrf_proof(input);
        let public_key = selector.get_public_key();

        // Verify the proof
        let is_valid = selector.verify_vrf_proof(&public_key, input, &output);
        assert!(is_valid, "VRF proof verification failed");
    }

    #[test]
    fn test_node_selection() {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let mut selector = VrfNodeSelector::new(node_id);

        // Create some test nodes
        let nodes: Vec<PeerId> = (0..5)
            .map(|_| PeerId::from(Keypair::generate_ed25519().public()))
            .collect();

        let result = selector.select_mpc_nodes(&nodes, 1, 1);

        assert_eq!(result.selected_nodes.len(), 1);
        assert_eq!(result.threshold, 3);
        assert_eq!(result.total_nodes, 5);
        assert_eq!(result.selection_round, 1);
    }

    #[test]
    fn test_selection_consistency() {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let mut selector = VrfNodeSelector::new(node_id);

        let nodes: Vec<PeerId> = (0..5)
            .map(|_| PeerId::from(Keypair::generate_ed25519().public()))
            .collect();

        let result1 = selector.select_mpc_nodes(&nodes, 3, 1);
        let result2 = selector.select_mpc_nodes(&nodes, 3, 1);

        // Same round should produce same result
        assert_eq!(result1.selected_nodes.len(), result2.selected_nodes.len());
        assert_eq!(result1.threshold, result2.threshold);
        assert_eq!(result1.total_nodes, result2.total_nodes);
        assert_eq!(result1.selection_round, result2.selection_round);

        // The selected nodes should be the same (deterministic VRF)
        assert_eq!(result1.selected_nodes, result2.selected_nodes);
    }
}
