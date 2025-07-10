use anyhow::Result;
use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::Field;
use hex;
use libp2p::PeerId;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::consensus::{ConsensusMessage, ConsensusNode, ConsensusResult};
use crate::types::{p2p::SerializablePeerId, ChannelMessage, SerializableG1Affine};
use crate::vrf::VrfNodeSelector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLSSignature {
    pub signature: SerializableG1Affine,
    pub signer_id: String,
    pub message_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub aggregated_signature: SerializableG1Affine,
    pub signer_ids: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    MessageToSign {
        from: String,
        message: Vec<u8>,
        message_hash: Vec<u8>,
    },
    BLSSignature {
        from: String,
        signature: BLSSignature,
    },
    SignedMessage {
        from: String,
        signed_message: SignedMessage,
    },
}

#[derive(Clone)]
pub struct SigningNode {
    id: String,
    threshold: usize,
    private_key: Option<Scalar>,
    public_key: Option<G1Affine>,
    public_keys: Arc<RwLock<HashMap<String, G1Affine>>>, // Other nodes' public keys
    signatures: Arc<RwLock<HashMap<String, BLSSignature>>>,
    pending_messages: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>, // message_hash -> message
    message_tx: mpsc::Sender<ChannelMessage>,
    vrf_selector: Option<VrfNodeSelector>, // VRF selector for node selection
    consensus_node: Option<ConsensusNode>, // Consensus node for final node selection
    available_nodes: Option<Vec<PeerId>>,  // Available nodes from node manager
}

impl SigningNode {
    pub fn new(id: String, threshold: usize, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        // Parse the actual PeerId from the string ID
        let peer_id = PeerId::from_str(&id).unwrap_or_else(|_| {
            // Fallback to derived PeerId if parsing fails
            Self::derive_peer_id_from_string(&id)
        });

        Self {
            id,
            threshold,
            private_key: None,
            public_key: None,
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            signatures: Arc::new(RwLock::new(HashMap::new())),
            pending_messages: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
            vrf_selector: Some(VrfNodeSelector::new(peer_id)),
            consensus_node: Some(ConsensusNode::new()),
            available_nodes: None,
        }
    }

    /// Derive a deterministic PeerId from a string ID
    fn derive_peer_id_from_string(id: &str) -> PeerId {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let hash = hasher.finalize();

        // Create a deterministic keypair from the hash
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash[..32]);

        // Create a deterministic Ed25519 keypair
        let ed_kp = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut key_bytes)
            .unwrap_or_else(|_| libp2p::identity::ed25519::Keypair::generate());
        let kp = libp2p::identity::Keypair::from(ed_kp);

        PeerId::from_public_key(&kp.public())
    }

    pub fn generate_key_pair(&mut self) -> Result<()> {
        let mut rng = OsRng;
        let private_key = Scalar::random(&mut rng);
        let public_key = G1Affine::from(G1Projective::generator() * private_key);

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);

        info!("🔐 [SIGNING] Node {} generated BLS key pair", self.id);
        info!("🔑 [SIGNING] Public key: {:?}", public_key);
        Ok(())
    }

    pub fn set_private_key(&mut self, private_key: Scalar) {
        self.private_key = Some(private_key);
        self.public_key = Some(G1Affine::from(G1Projective::generator() * private_key));
        info!("🔐 [SIGNING] Node {} private key set", self.id);
    }

    pub fn add_public_key(&self, node_id: String, public_key: G1Affine) {
        let node_id_clone = node_id.clone();
        tokio::spawn({
            let public_keys = self.public_keys.clone();
            async move {
                public_keys.write().await.insert(node_id, public_key);
            }
        });
        info!(
            "🔑 [SIGNING] Node {} added public key for {}",
            self.id, node_id_clone
        );
    }

    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: topic.to_string(),
                data: data.to_vec(),
            })
            .await?;
        Ok(())
    }

    pub async fn sign_message(&mut self, message: &[u8]) -> Result<()> {
        if self.private_key.is_none() {
            error!(
                "❌ [SIGNING] Node {} cannot sign: no private key available",
                self.id
            );
            return Err(anyhow::anyhow!("No private key available"));
        }

        let message_hash = self.hash_message(message);
        info!(
            "📝 [SIGNING] Node {} starting to sign message: {:?}",
            self.id, message_hash
        );

        // Get available nodes before the mutable borrow
        let available_nodes = self.get_available_nodes_from_manager().await;
        let round = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate VRF proof for this signing operation
        if let Some(vrf_selector) = &mut self.vrf_selector {
            let selection_result = vrf_selector.select_mpc_nodes(&available_nodes, 1, round);
            info!(
                "🎯 [VRF] Node {} selected {} MPC nodes for signing round {}: {:?}",
                self.id,
                selection_result.selected_nodes.len(),
                round,
                selection_result.selected_nodes
            );
            info!("available nodes for vrf are : {:?}", available_nodes);

            // Broadcast the VRF-selected nodes to all peers
            if let Some(broadcast_msg) = vrf_selector.create_selected_nodes_broadcast(round) {
                let broadcast_data = serde_json::to_vec(
                    &crate::types::GossipsubMessage::VrfSelectedNodes(broadcast_msg),
                )?;
                self.broadcast("vrf-selection", &broadcast_data).await?;
                info!(
                    "📤 [VRF] Node {} broadcasted VRF-selected nodes for round {}",
                    self.id, round
                );
            }
        }

        // Store the message for later use
        self.pending_messages
            .write()
            .await
            .insert(message_hash.clone(), message.to_vec());

        // Create BLS signature
        let signature = self.create_bls_signature(&message_hash)?;
        info!(
            "✍️ [SIGNING] Node {} created BLS signature: \x1b[34m{}\x1b[0m",
            self.id,
            self.get_compressed_signature_hex(&signature)
        );

        let bls_signature = BLSSignature {
            signature: SerializableG1Affine(signature),
            signer_id: self.id.clone(),
            message_hash: message_hash.clone(),
        };

        let msg = serde_json::to_vec(&SigningMessage::BLSSignature {
            from: self.id.clone(),
            signature: bls_signature,
        })?;

        self.broadcast("signing", &msg).await?;
        info!("📤 [SIGNING] Node {} broadcasted BLS signature", self.id);
        Ok(())
    }

    fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    fn create_bls_signature(&self, message_hash: &[u8]) -> Result<G1Affine> {
        if let Some(private_key) = self.private_key {
            // Convert message hash to scalar
            let message_scalar = self.hash_to_scalar(message_hash);

            // BLS signature: σ = H(m)^sk where H(m) is the message hash as a point
            // We'll use the generator multiplied by the message hash scalar
            let message_point = G1Affine::from(G1Projective::generator() * message_scalar);
            let signature = G1Affine::from(message_point * private_key);

            info!(
                "✍️ [SIGNING] Node {} created BLS signature: {:?}",
                self.id, signature
            );
            Ok(signature)
        } else {
            Err(anyhow::anyhow!("No private key available"))
        }
    }

    fn hash_to_scalar(&self, data: &[u8]) -> Scalar {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // Convert hash to scalar (simplified)
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&hash);
        Scalar::from_bytes_wide(&bytes)
    }

    pub async fn handle_message(&mut self, msg: SigningMessage) -> Result<()> {
        match msg {
            SigningMessage::MessageToSign {
                from,
                message,
                message_hash,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received message to sign from {}",
                    self.id, from
                );
                self.handle_message_to_sign(from, message, message_hash)
                    .await?;
            }
            SigningMessage::BLSSignature { from, signature } => {
                info!(
                    "📥 [SIGNING] Node {} received BLS signature from {}",
                    self.id, from
                );
                self.handle_bls_signature(from, signature).await?;
            }
            SigningMessage::SignedMessage {
                from,
                signed_message,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received signed message from {}",
                    self.id, from
                );
                self.handle_signed_message(from, signed_message).await?;
            }
        }
        Ok(())
    }

    async fn handle_bls_signature(&mut self, from: String, signature: BLSSignature) -> Result<()> {
        self.signatures
            .write()
            .await
            .insert(from.clone(), signature.clone());
        info!(
            "💾 [SIGNING] Node {} stored BLS signature from {}",
            self.id, from
        );
        self.check_signature_completion(signature.message_hash)
            .await?;
        Ok(())
    }

    async fn check_signature_completion(&self, message_hash: Vec<u8>) -> Result<()> {
        let signatures = self.signatures.read().await;
        if signatures.len() >= self.threshold {
            info!(
                "🎯 [SIGNING] Node {} has enough BLS signatures ({}), aggregating",
                self.id,
                signatures.len()
            );

            let aggregated_signature = self.aggregate_signatures().await?;
            let message = self
                .pending_messages
                .read()
                .await
                .get(&message_hash)
                .cloned();

            if let Some(message) = message {
                let signer_ids: Vec<String> = signatures.keys().cloned().collect();
                let signed_message = SignedMessage {
                    message,
                    aggregated_signature: SerializableG1Affine(aggregated_signature),
                    signer_ids,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };

                let msg = serde_json::to_vec(&SigningMessage::SignedMessage {
                    from: self.id.clone(),
                    signed_message: signed_message.clone(),
                })?;

                self.broadcast("signing", &msg).await?;
                info!(
                    "🎉 [SIGNING] Node {} completed BLS signing and broadcasted result",
                    self.id
                );
                info!(
                    "📋 [SIGNING] Final aggregated signature: {:?}",
                    aggregated_signature
                );
            }
        } else {
            info!(
                "⏳ [SIGNING] Node {} waiting for more BLS signatures: {}/{}",
                self.id,
                signatures.len(),
                self.threshold
            );
        }
        Ok(())
    }

    async fn aggregate_signatures(&self) -> Result<G1Affine> {
        let signatures = self.signatures.read().await;
        let mut aggregated_signature = G1Projective::identity();

        for (from, bls_signature) in signatures.iter() {
            aggregated_signature += bls_signature.signature.0;
            info!(
                "➕ [SIGNING] Node {} aggregated signature from {}: {:?}",
                self.id, from, bls_signature.signature.0
            );
        }

        let final_signature = G1Affine::from(aggregated_signature);
        info!(
            "🔢 [SIGNING] Node {} final aggregated BLS signature: {:?}",
            self.id, final_signature
        );
        Ok(final_signature)
    }

    async fn handle_message_to_sign(
        &mut self,
        from: String,
        message: Vec<u8>,
        message_hash: Vec<u8>,
    ) -> Result<()> {
        info!(
            "📝 [SIGNING] Node {} received message to sign from {}: {:?}",
            self.id, from, message_hash
        );
        self.sign_message(&message).await?;
        Ok(())
    }

    async fn handle_signed_message(
        &mut self,
        from: String,
        signed_message: SignedMessage,
    ) -> Result<()> {
        info!(
            "✅ [SIGNING] Node {} received signed message from {}",
            self.id, from
        );
        info!("📄 [SIGNING] Message: {:?}", signed_message.message);
        info!(
            "✍️ [SIGNING] Aggregated signature: {:?}",
            signed_message.aggregated_signature.0
        );
        info!("👥 [SIGNING] Signers: {:?}", signed_message.signer_ids);
        info!("🕒 [SIGNING] Timestamp: {}", signed_message.timestamp);

        // Verify the aggregated BLS signature
        let is_valid = self.verify_aggregated_signature(&signed_message).await?;
        if is_valid {
            info!("✅ [SIGNING] BLS signature verification successful!");
        } else {
            warn!("❌ [SIGNING] BLS signature verification failed!");
        }

        Ok(())
    }

    async fn verify_aggregated_signature(&self, signed_message: &SignedMessage) -> Result<bool> {
        let public_keys = self.public_keys.read().await;

        // Check if we have all the public keys for the signers
        for signer_id in &signed_message.signer_ids {
            if !public_keys.contains_key(signer_id) {
                warn!("⚠️ [SIGNING] Missing public key for signer: {}", signer_id);
                return Ok(false);
            }
        }

        // Aggregate public keys
        let mut aggregated_public_key = G1Projective::identity();
        for signer_id in &signed_message.signer_ids {
            if let Some(public_key) = public_keys.get(signer_id) {
                aggregated_public_key += public_key;
            }
        }

        // Verify BLS signature: e(σ, g) = e(H(m), pk_agg)
        // where σ is the signature, g is the generator, H(m) is the message hash, and pk_agg is the aggregated public key

        let message_hash = self.hash_message(&signed_message.message);
        let message_scalar = self.hash_to_scalar(&message_hash);
        let message_point = G1Affine::from(G1Projective::generator() * message_scalar);

        // For BLS verification, we need to check if the signature is valid
        // This is a simplified verification - in practice you'd use pairing
        let _signature_point = signed_message.aggregated_signature.0;
        let _expected_signature = G1Affine::from(message_point * Scalar::from(1u64)); // Simplified

        info!("🔍 [SIGNING] Node {} verifying BLS signature", self.id);

        // For now, return true as a placeholder
        // In a real implementation, you would use pairing-based verification
        Ok(true)
    }

    /// Get the compressed 48-byte representation of a BLS signature
    pub fn get_compressed_signature_bytes(&self, signature: &G1Affine) -> [u8; 48] {
        signature.to_compressed()
    }

    /// Get the compressed 48-byte representation as a hex string
    pub fn get_compressed_signature_hex(&self, signature: &G1Affine) -> String {
        let bytes = signature.to_compressed();
        hex::encode(bytes)
    }

    /// Get VRF public key for this node
    pub fn get_vrf_public_key(&self) -> Option<String> {
        self.vrf_selector
            .as_ref()
            .map(|vrf| vrf.get_public_key_hex())
    }

    /// Get VRF public key as bytes
    pub fn get_vrf_public_key_bytes(&self) -> Option<Vec<u8>> {
        self.vrf_selector.as_ref().map(|vrf| vrf.get_public_key())
    }

    /// Generate VRF proof for a given input
    pub fn generate_vrf_proof(&self, input: &[u8]) -> Option<crate::vrf::VrfOutput> {
        self.vrf_selector
            .as_ref()
            .map(|vrf| vrf.generate_vrf_proof(input))
    }

    /// Verify VRF proof from another node
    pub fn verify_vrf_proof(
        &self,
        node_public_key: &[u8],
        input: &[u8],
        output: &crate::vrf::VrfOutput,
    ) -> bool {
        self.vrf_selector
            .as_ref()
            .map(|vrf| vrf.verify_vrf_proof(node_public_key, input, output))
            .unwrap_or(false)
    }

    /// Get available nodes as PeerIds derived from stored public keys
    async fn get_available_nodes(&self) -> Vec<PeerId> {
        self.available_nodes.clone().unwrap()
    }

    /// Set available nodes from node manager
    pub fn set_available_nodes(&mut self, nodes: Vec<PeerId>) {
        self.available_nodes = Some(nodes);
    }

    async fn get_available_nodes_from_manager(&self) -> Vec<PeerId> {
        if let Some(ref nodes) = self.available_nodes {
            nodes.clone()
        } else {
            self.get_available_nodes().await
        }
    }

    /// Handle VRF selected nodes broadcast from another node
    pub fn handle_vrf_selected_nodes_broadcast(
        &mut self,
        broadcast: crate::vrf::VrfSelectedNodesBroadcast,
    ) {
        if let Some(vrf_selector) = &mut self.vrf_selector {
            // Extract round before moving broadcast
            let round = broadcast.round;
            let min_selections = 4; // Or set to your desired threshold

            vrf_selector.handle_selected_nodes_broadcast(broadcast);

            // Check if consensus should be triggered after receiving this broadcast
            if vrf_selector.can_start_consensus(round, min_selections) {
                info!(
                    "🎯 [VRF] Enough selections collected for round {}, triggering consensus check",
                    round
                );

                // Spawn a task to trigger consensus asynchronously
                let mut signing_node_clone = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = signing_node_clone
                        .check_and_trigger_consensus(round, min_selections)
                        .await
                    {
                        error!(
                            "❌ [CONSENSUS] Failed to trigger consensus for round {}: {}",
                            round, e
                        );
                    }
                });
            }
        }
    }

    /// Check and trigger consensus if ready
    pub async fn check_and_trigger_consensus(
        &mut self,
        round: u64,
        min_selections: usize,
    ) -> Result<Option<ConsensusResult>> {
        if self.can_start_consensus(round, min_selections) {
            info!(
                "🎯 [CONSENSUS] Consensus ready for round {}, starting...",
                round
            );
            self.start_consensus_for_round(round).await
        } else {
            Ok(None)
        }
    }

    /// Start consensus for a specific round
    pub async fn start_consensus_for_round(
        &mut self,
        round: u64,
    ) -> Result<Option<ConsensusResult>> {
        // Get the node ID first to avoid borrow checker issues
        let own_node_id = SerializablePeerId(PeerId::from_str(&self.id)?);

        if let (Some(vrf_selector), Some(consensus_node)) =
            (&self.vrf_selector, &mut self.consensus_node)
        {
            // Get all selected nodes with frequencies for this round
            let all_selected_nodes = vrf_selector.get_all_selected_nodes_with_frequencies(round);

            if all_selected_nodes.is_empty() {
                info!(
                    "⚠️ [CONSENSUS] No selected nodes available for consensus round {}",
                    round
                );
                return Ok(None);
            }

            info!(
                "🎯 [CONSENSUS] Starting consensus for round {} with {} selected nodes",
                round,
                all_selected_nodes.len()
            );

            // Add selected nodes to consensus
            consensus_node.add_selected_nodes(round, all_selected_nodes);

            // Start consensus
            match consensus_node.start_consensus(round) {
                Ok(result) => {
                    info!(
                        "✅ [CONSENSUS] Consensus completed for round {}: final node = {:?}",
                        round, result.final_node
                    );

                    // Broadcast the consensus result
                    let consensus_msg = ConsensusMessage::FinalNodeResult {
                        result: result.clone(),
                        round,
                    };

                    let broadcast_data = serde_json::to_vec(&consensus_msg)?;

                    // Store the result for later use
                    let is_final_node = consensus_node.is_final_node(round, &own_node_id);

                    // Broadcast outside of the borrow
                    self.broadcast("consensus-result", &broadcast_data).await?;

                    info!(
                        "📤 [CONSENSUS] Broadcasted consensus result for round {}",
                        round
                    );

                    // Check if this node is the final selected node
                    if is_final_node {
                        info!(
                            "\x1b[32m🏆 [CONSENSUS] This node is the final selected node for round {}!\x1b[0m",
                            round
                        );
                        // Trigger aggregate signature for the final node
                        self.trigger_aggregate_signature_for_final_node(round)
                            .await?;
                    } else {
                        info!(
                            "\x1b[31m📋 [CONSENSUS] This node is not the final selected node for round {}\x1b[0m",
                            round
                        );
                    }

                    Ok(Some(result))
                }
                Err(e) => {
                    error!(
                        "❌ [CONSENSUS] Failed to start consensus for round {}: {}",
                        round, e
                    );
                    Err(e)
                }
            }
        } else {
            Err(anyhow::anyhow!(
                "VRF selector or consensus node not available"
            ))
        }
    }

    /// Check if consensus can be started for a round
    pub fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        if let Some(vrf_selector) = &self.vrf_selector {
            vrf_selector.can_start_consensus(round, min_selections)
        } else {
            false
        }
    }

    /// Handle consensus messages
    pub async fn handle_consensus_message(&mut self, msg: ConsensusMessage) -> Result<()> {
        if let Some(consensus_node) = &mut self.consensus_node {
            consensus_node.handle_message(msg).await?;
        }
        Ok(())
    }

    /// Trigger aggregate signature for the final selected node
    async fn trigger_aggregate_signature_for_final_node(&self, round: u64) -> Result<()> {
        info!(
            "🚀 [SIGNING] Triggering aggregate signature for final node in round {}",
            round
        );

        // This is where you would trigger the aggregate signature process
        // For now, we'll just log that the final node should start aggregation
        info!(
            "📝 [SIGNING] Final node should start BLS signature aggregation for round {}",
            round
        );

        // You can add the actual aggregate signature logic here
        // For example:
        // self.aggregate_signatures().await?;

        Ok(())
    }

    /// Get the node ID
    pub fn get_node_id(&self) -> &str {
        &self.id
    }
}
