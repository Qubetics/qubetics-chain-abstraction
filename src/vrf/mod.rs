use crate::types::p2p::SerializablePeerId;
use anyhow::Result;
use ecvrf::{keygen, prove, verify, VrfPk, VrfProof, VrfSk};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

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

/// VRF-based node selector using ecvrf
#[derive(Debug, Clone)]
pub struct VrfNodeSelector {
    vrf_secret_key: VrfSk,
    vrf_public_key: VrfPk,
    node_id: PeerId,
    selection_round: u64,
    submissions: HashMap<u64, HashMap<PeerId, VrfOutput>>,
    results: HashMap<u64, NodeSelectionResult>,
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

        debug!("Selected nodes: {:?}", selected_nodes);

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

        println!("Generated proof: {} bytes", output.proof.len());
        println!("Generated hash: {:?} bytes", output.hash.len());
        println!("Generated value: {}", output.value);
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

        let result = selector.select_mpc_nodes(&nodes, 3, 1);

        assert_eq!(result.selected_nodes.len(), 3);
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
