use crate::types::p2p::SerializablePeerId;
use anyhow::{anyhow, bail, Result};
use blake3::hash;
use ecvrf::{keygen, prove, verify, VrfPk, VrfProof, VrfSk};
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

use super::types::{
    NodeSelectionResult, VrfOutput, VrfSelectedNodesBroadcast, VrfSelectionMessage,
};

#[derive(Debug, Clone)]
pub struct VrfNodeSelector {
    vrf_secret_key: VrfSk,
    vrf_public_key: VrfPk,
    node_id: PeerId,
    selection_round: u64,
    submissions: HashMap<u64, HashMap<PeerId, VrfOutput>>,
    results: HashMap<u64, NodeSelectionResult>,
    received_selections: HashMap<u64, HashMap<SerializablePeerId, VrfSelectedNodesBroadcast>>,
    /// Operation type that triggered VRF for each round (e.g., "global_clock", "bitcoin", "ethereum")
    operation_types_by_round: HashMap<u64, String>,
}

impl VrfNodeSelector {
    const VRF_PROOF_DOMAIN: &'static [u8] = b"adkg-vrf-challenge";
    const SELECTION_CONTEXT: &'static [u8] = b"mpc-node-vrf-selection";

    pub fn new(node_id: PeerId) -> Self {
        let (vrf_secret_key, vrf_public_key) = keygen();

        Self {
            vrf_secret_key,
            vrf_public_key,
            node_id,
            selection_round: 0,
            submissions: HashMap::new(),
            results: HashMap::new(),
            received_selections: HashMap::new(),
            operation_types_by_round: HashMap::new(),
        }
    }

    /// Store the operation type for this round
    pub fn set_operation_type(&mut self, round: u64, operation_type: String) {
        self.operation_types_by_round.insert(round, operation_type);
    }

    /// Get the operation type for this round
    pub fn get_operation_type(&self, round: u64) -> Option<&String> {
        self.operation_types_by_round.get(&round)
    }

    pub fn ensure_local_submission(&mut self, round: u64) {
        let node_id = self.node_id;
        let already_present = {
            let round_entry = self.submissions.entry(round).or_default();
            round_entry.contains_key(&node_id)
        };

        if !already_present {
            let proof = self.generate_selection_proof(round);
            self.submissions
                .entry(round)
                .or_default()
                .insert(node_id, proof);
        }
    }

    fn selection_input(round: u64, node_id: &PeerId) -> Vec<u8> {
        let mut input = Vec::with_capacity(
            Self::SELECTION_CONTEXT.len() + std::mem::size_of::<u64>() + node_id.to_bytes().len(),
        );
        input.extend_from_slice(Self::SELECTION_CONTEXT);
        input.extend_from_slice(&round.to_le_bytes());
        input.extend_from_slice(&node_id.to_bytes());
        input
    }

    fn synthetic_submission(round: u64, node_id: &PeerId) -> VrfOutput {
        let mut seed = Vec::new();
        seed.extend_from_slice(b"SYNTHETIC_VRF");
        seed.extend_from_slice(&round.to_le_bytes());
        seed.extend_from_slice(&node_id.to_bytes());

        let digest = hash(&seed);
        let mut proof = Vec::with_capacity(96);
        while proof.len() < 96 {
            proof.extend_from_slice(digest.as_bytes());
        }
        proof.truncate(96);

        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&digest.as_bytes()[..8]);

        VrfOutput {
            proof,
            hash: digest.as_bytes().to_vec(),
            value: u64::from_le_bytes(value_bytes),
        }
    }

    fn vrf_challenge(input: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::VRF_PROOF_DOMAIN);
        hasher.update(input);
        hasher.finalize().into()
    }

    fn selection_value(output_hash: &[u8]) -> u64 {
        let digest = hash(output_hash);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(bytes)
    }

    pub fn generate_vrf_proof(&self, input: &[u8]) -> VrfOutput {
        let challenge = Self::vrf_challenge(input);
        let (hash, proof) = prove(&challenge, &self.vrf_secret_key);
        let value = Self::selection_value(&hash);

        VrfOutput {
            proof: proof.to_bytes().to_vec(),
            hash: hash.to_vec(),
            value,
        }
    }

    pub fn verify_vrf_proof(
        &self,
        node_public_key: &[u8],
        input: &[u8],
        output: &VrfOutput,
    ) -> bool {
        let pubkey = match VrfPk::from_bytes(node_public_key.try_into().unwrap_or(&[0; 32])) {
            Ok(pk) => pk,
            Err(_) => {
                debug!("Failed to deserialize public key");
                return false;
            }
        };

        let proof = match VrfProof::from_bytes(&output.proof.clone().try_into().unwrap_or([0; 96]))
        {
            Ok(p) => p,
            Err(_) => {
                debug!("Failed to deserialize VRF proof");
                return false;
            }
        };

        let challenge = Self::vrf_challenge(input);
        let hash: [u8; 32] = output.hash.clone().try_into().unwrap_or([0; 32]);
        verify(&challenge, &pubkey, &hash, &proof)
    }

    pub fn generate_selection_proof(&self, round: u64) -> VrfOutput {
        let input = Self::selection_input(round, &self.node_id);
        self.generate_vrf_proof(&input)
    }

    pub fn select_mpc_nodes(
        &mut self,
        available_nodes: &[PeerId],
        threshold: usize,
        round: u64,
        allow_synthetic: bool,
    ) -> Result<NodeSelectionResult> {
        if available_nodes.is_empty() {
            bail!("VRF selection requested without available nodes");
        }

        if threshold == 0 {
            bail!("VRF selection threshold must be greater than zero");
        }

        info!(
            "Starting VRF-based MPC node selection for round {} ({} candidates, threshold {})",
            round,
            available_nodes.len(),
            threshold
        );

        let allowed: HashSet<PeerId> = available_nodes.iter().cloned().collect();
        let submissions_for_round = self.submissions.entry(round).or_default().clone();

        let mut working_set = submissions_for_round;

        if allow_synthetic {
            for peer_id in &allowed {
                working_set
                    .entry(*peer_id)
                    .or_insert_with(|| Self::synthetic_submission(round, peer_id));
            }
        }

        if working_set.is_empty() {
            bail!(
                "no VRF submissions available for round {} ({} candidates)",
                round,
                allowed.len()
            );
        }

        let mut node_vrf_pairs: Vec<(SerializablePeerId, u64)> = working_set
            .iter()
            .filter(|(peer_id, _)| allowed.contains(peer_id))
            .map(|(peer_id, output)| (SerializablePeerId(*peer_id), output.value))
            .collect();

        if node_vrf_pairs.len() < threshold {
            bail!(
                "only {} VRF submissions available for round {}, need {}",
                node_vrf_pairs.len(),
                round,
                threshold
            );
        }

        node_vrf_pairs.sort_by(|a, b| a.1.cmp(&b.1));

        let selected_nodes: Vec<SerializablePeerId> = node_vrf_pairs
            .into_iter()
            .take(threshold)
            .map(|(node_id, _)| node_id)
            .collect();

        info!("Selected nodes: {:?}", selected_nodes);

        let vrf_outputs: HashMap<SerializablePeerId, VrfOutput> = working_set
            .into_iter()
            .filter(|(peer_id, _)| allowed.contains(peer_id))
            .map(|(peer_id, output)| (SerializablePeerId(peer_id), output))
            .collect();

        let result = NodeSelectionResult {
            selected_nodes: selected_nodes.clone(),
            vrf_outputs,
            threshold,
            total_nodes: available_nodes.len(),
            selection_round: round,
        };

        self.results.insert(round, result.clone());
        self.selection_round = round;

        Ok(result)
    }

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

    pub fn get_selection_result(&self, round: u64) -> Option<&NodeSelectionResult> {
        self.results.get(&round)
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.vrf_public_key.to_bytes().to_vec()
    }

    pub fn get_public_key_hex(&self) -> String {
        hex::encode(self.vrf_public_key.to_bytes())
    }

    pub fn get_secret_key(&self) -> Vec<u8> {
        self.vrf_secret_key.to_bytes().to_vec()
    }

    pub fn get_secret_key_hex(&self) -> String {
        hex::encode(self.vrf_secret_key.to_bytes())
    }

    pub async fn handle_message(&mut self, msg: VrfSelectionMessage) -> Result<()> {
        match msg {
            VrfSelectionMessage::VrfSubmission {
                node_id,
                vrf_output,
                public_key,
                round,
            } => {
                self.handle_vrf_submission(node_id.0, vrf_output, public_key, round)
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
        public_key: Vec<u8>,
        round: u64,
    ) -> Result<()> {
        debug!(
            "Received VRF submission from node {} for round {}",
            node_id, round
        );

        let input = Self::selection_input(round, &node_id);
        if public_key.is_empty() {
            return Err(anyhow!(
                "node {} submitted VRF output without public key for round {}",
                node_id,
                round
            ));
        }

        if !self.verify_vrf_proof(&public_key, &input, &vrf_output) {
            return Err(anyhow!(
                "invalid VRF submission from node {} for round {}",
                node_id,
                round
            ));
        }

        self.submissions
            .entry(round)
            .or_default()
            .insert(node_id, vrf_output);

        Ok(())
    }

    async fn handle_selection_result(
        &mut self,
        result: NodeSelectionResult,
        round: u64,
    ) -> Result<()> {
        debug!(
            "Received selection result for round {}: {} nodes selected",
            round,
            result.selected_nodes.len()
        );

        self.results.insert(round, result);

        if self.is_selected(round) {
            debug!("This node is selected for MPC in round {}", round);
        } else {
            debug!("This node is not selected for MPC in round {}", round);
        }

        Ok(())
    }

    pub fn get_current_round(&self) -> u64 {
        self.selection_round
    }

    pub fn advance_round(&mut self) {
        self.selection_round += 1;
    }

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
                operation_type: self.operation_types_by_round.get(&round).cloned(),
            })
        } else {
            None
        }
    }

    pub fn handle_selected_nodes_broadcast(
        &mut self,
        broadcast: VrfSelectedNodesBroadcast,
        sender_peer_id: PeerId,
        total_nodes: usize,
    ) {
        info!(
            "📥 [VRF] Received VRF selected nodes broadcast from node {} (claimed selector: {}) for round {}: {} nodes selected",
            sender_peer_id,
            broadcast.selector_node_id.0,
            broadcast.round,
            broadcast.selected_nodes.len()
        );

        // SECURITY FIX: Use authenticated sender_peer_id for deduplication instead of message-controlled selector_node_id
        // This prevents spoofing attacks where an attacker sends multiple broadcasts with different selector_node_id values
        let round = broadcast.round;
        let authenticated_sender = SerializablePeerId(sender_peer_id);
        self.received_selections
            .entry(round)
            .or_default()
            .insert(authenticated_sender, broadcast);

        let all_selected = self.get_all_selected_nodes_for_round(round);
        info!("All selected nodes for round {}: {:?}", round, all_selected);
        info!(
            "🔄 [VRF] Updating aggregated selections for round {}...",
            round
        );

        let min_selections = total_nodes;
        if self.can_start_consensus(round, min_selections) {
            info!(
                "🎯 [VRF] Enough selections collected for round {}, consensus can be started",
                round
            );
        }
    }

    pub fn get_received_selections_for_round(&self, round: u64) -> Vec<&VrfSelectedNodesBroadcast> {
        self.received_selections
            .get(&round)
            .map(|selections| selections.values().collect())
            .unwrap_or_default()
    }

    pub fn get_all_selected_nodes_for_round(&self, round: u64) -> Vec<SerializablePeerId> {
        let mut all_selected = std::collections::HashSet::new();
        let mut own_selections = Vec::new();
        let mut received_selections = Vec::new();

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
            info!(
                "⚠️ [VRF] No own selections found for round {} - this may be due to UTXO unavailability",
                round
            );
        }

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

    pub fn get_all_selected_nodes_with_frequencies(&self, round: u64) -> Vec<SerializablePeerId> {
        let mut all_selected = Vec::new();

        if let Some(result) = self.results.get(&round) {
            for node in &result.selected_nodes {
                all_selected.push(node.clone());
            }
        }

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

        let is_valid = selector.verify_vrf_proof(&public_key, input, &output);
        assert!(is_valid, "VRF proof verification failed");
    }

    #[test]
    fn test_node_selection() {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let mut selector = VrfNodeSelector::new(node_id);
        selector.ensure_local_submission(1);

        let nodes: Vec<PeerId> = (0..5)
            .map(|_| PeerId::from(Keypair::generate_ed25519().public()))
            .collect();

        let result = selector
            .select_mpc_nodes(&nodes, 1, 1, true)
            .expect("selection should succeed");

        assert_eq!(result.selected_nodes.len(), 1);
        assert_eq!(result.threshold, 1);
        assert_eq!(result.total_nodes, 5);
        assert_eq!(result.selection_round, 1);
    }

    #[test]
    fn test_selection_consistency() {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let mut selector = VrfNodeSelector::new(node_id);
        selector.ensure_local_submission(1);

        let nodes: Vec<PeerId> = (0..5)
            .map(|_| PeerId::from(Keypair::generate_ed25519().public()))
            .collect();

        let result1 = selector
            .select_mpc_nodes(&nodes, 3, 1, true)
            .expect("first selection should succeed");
        let result2 = selector
            .select_mpc_nodes(&nodes, 3, 1, true)
            .expect("second selection should succeed");

        assert_eq!(result1.selected_nodes, result2.selected_nodes);
    }
}
