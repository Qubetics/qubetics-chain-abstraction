use anyhow::Result;
use bls12_381::Scalar;
use hex;
use libp2p::PeerId;
use rand::rngs::OsRng;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::consensus::{ConsensusMessage, ConsensusNode, ConsensusResult};
use crate::types::{p2p::SerializablePeerId, ChannelMessage};
use crate::vrf::VrfNodeSelector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDSASignature {
    pub signature: Vec<u8>, // 65-byte recoverable signature
    pub signer_id: String,
    pub message_hash: Vec<u8>,
    pub recovery_id: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub aggregated_signature: Vec<u8>, // ECDSA signature
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
    ECDSASignature {
        from: String,
        signature: ECDSASignature,
    },
    SignedMessage {
        from: String,
        signed_message: SignedMessage,
    },
    RequestSignatures {
        round: u64,
        final_node_id: String,
        message: String,
    },
}

#[derive(Clone)]
pub struct SigningNode {
    id: String,
    threshold: usize,
    private_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    public_keys: Arc<RwLock<HashMap<String, PublicKey>>>, // Other nodes' public keys
    signatures: Arc<RwLock<HashMap<String, ECDSASignature>>>,
    signatures_by_round: Arc<RwLock<HashMap<u64, HashMap<String, ECDSASignature>>>>, // round -> node_id -> signature
    final_nodes_by_round: Arc<RwLock<HashMap<u64, String>>>, // round -> final_node_id
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
            signatures_by_round: Arc::new(RwLock::new(HashMap::new())),
            final_nodes_by_round: Arc::new(RwLock::new(HashMap::new())),
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
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (private_key, public_key) = secp.generate_keypair(&mut rng);

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);

        info!("🔐 [SIGNING] Node {} generated ECDSA key pair", self.id);
        info!("🔑 [SIGNING] Public key: {:?}", public_key);
        Ok(())
    }

    pub fn set_private_key(&mut self, private_key: SecretKey) {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        info!("🔐 [SIGNING] Node {} private key set", self.id);
    }

    pub fn set_private_key_from_bls_scalar(&mut self, bls_scalar: Scalar) {
        // Convert BLS scalar to secp256k1 secret key
        let scalar_bytes = bls_scalar.to_bytes();
        let secret_key = SecretKey::from_slice(&scalar_bytes).unwrap_or_else(|_| {
            // If conversion fails, generate a new key
            let secp = Secp256k1::new();
            let (sk, _) = secp.generate_keypair(&mut OsRng);
            sk
        });

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        self.private_key = Some(secret_key);
        self.public_key = Some(public_key);
        info!(
            "🔐 [SIGNING] Node {} private key set from BLS scalar",
            self.id
        );
    }

    pub fn add_public_key(&self, node_id: String, public_key: PublicKey) {
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

        // Create ECDSA signature
        let signature = self.create_ecdsa_signature(&message_hash)?;
        // Extract signature components
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let v: u64 = recovery_id.to_i32() as u64 + 35 + 1043 * 2; // ✅ use u64 to prevent overflow
        let r = &signature_bytes[0..32];
        let s = &signature_bytes[32..64];
        info!(
            "✍️ [SIGNING] Node {} created ECDSA signature: \x1b[34m{:?}\x1b[0m",
            self.id,
            signature.serialize_compact()
        );
        println!("\nSignature Components:");
        println!("  v: {}", v);
        println!("  r: 0x{}", hex::encode(r));
        println!("  s: 0x{}", hex::encode(s));

        let ecdsa_signature = ECDSASignature {
            signature: signature.serialize_compact().1.to_vec(),
            signer_id: self.id.clone(),
            message_hash: message_hash.clone(),
            recovery_id: signature.serialize_compact().0.to_i32() as u8,
        };

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(self.id.clone(), ecdsa_signature.clone());
            info!(
                "💾 [SIGNING] Node {} stored signature for round {}",
                self.id, round
            );
        }

        let msg = serde_json::to_vec(&crate::types::GossipsubMessage::Signing(
            SigningMessage::ECDSASignature {
                from: self.id.clone(),
                signature: ecdsa_signature,
            },
        ))?;

        self.broadcast("signing", &msg).await?;
        info!("📤 [SIGNING] Node {} broadcasted ECDSA signature", self.id);
        Ok(())
    }

    fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    fn create_ecdsa_signature(&self, message_hash: &[u8]) -> Result<RecoverableSignature> {
        if let Some(private_key) = self.private_key {
            let secp = Secp256k1::new();

            // Create a message from the hash
            let message = Message::from_digest_slice(message_hash)?;

            // Sign the message with recoverable signature
            let signature = secp.sign_ecdsa_recoverable(&message, &private_key);
            // Extract signature components
            let (recovery_id, signature_bytes) = signature.serialize_compact();
            let v: u64 = recovery_id.to_i32() as u64 + 35 + 1043 * 2; // ✅ use u64 to prevent overflow
            let r = &signature_bytes[0..32];
            let s = &signature_bytes[32..64];

            println!("\nSignature Components:");
            println!("  v: {}", v);
            println!("  r: 0x{}", hex::encode(r));
            println!("  s: 0x{}", hex::encode(s));

            // Create signed transaction
            let dummy_transaction = crate::rpc_server::DummyTransaction {
                to: "0xceb5057834CB4EdE0E59F9e91046B8cB96C72e9C".to_string(),
                value: "0x2386f26fc10000".to_string(), // 1 ETH in wei
                nonce: 0,
                gas_limit: 21000,
                gas_price: "0x3b9aca00".to_string(), // 2.5 gwei
                chain_id: 1043,
            };
            let signed_tx =
                crate::utils::transaction::create_signed_transaction(&dummy_transaction, r, s, v);
            println!("\nSigned Transaction (RLP): {:?}", &signed_tx);
            let raw_tx = format!("0x{}", hex::encode(&signed_tx));

            println!("\nRaw Transaction: {}", raw_tx);

            info!(
                "✍️ [SIGNING] Node {} created ECDSA signature: {:?}",
                self.id, signature
            );
            Ok(signature)
        } else {
            Err(anyhow::anyhow!("No private key available"))
        }
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
            SigningMessage::ECDSASignature { from, signature } => {
                info!(
                    "📥 [SIGNING] Node {} received ECDSA signature from {}",
                    self.id, from
                );
                self.handle_ecdsa_signature(from, signature).await?;
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
            SigningMessage::RequestSignatures {
                round,
                final_node_id,
                message,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received signature request for round {} from final node {}",
                    self.id, round, final_node_id
                );
                self.handle_signature_request(round, final_node_id, message)
                    .await?;
            }
        }
        Ok(())
    }

    async fn handle_ecdsa_signature(
        &mut self,
        from: String,
        signature: ECDSASignature,
    ) -> Result<()> {
        // Store in general signatures
        self.signatures
            .write()
            .await
            .insert(from.clone(), signature.clone());

        info!(
            "💾 [SIGNING] Node {} stored ECDSA signature from {}",
            self.id, from
        );

        // Check if this signature is for a specific round (from signatures-to-final-node topic)
        // If this node is the final node for any round, handle it as a signature for that round
        let round_to_handle = {
            let final_nodes = self.final_nodes_by_round.read().await;
            let mut found_round = None;
            for (round, final_node_id) in final_nodes.iter() {
                if final_node_id == &self.id {
                    found_round = Some(*round);
                    break;
                }
            }
            found_round
        };

        if let Some(round) = round_to_handle {
            // This node is the final node for this round, store the signature by round
            let should_aggregate = {
                let mut signatures_by_round = self.signatures_by_round.write().await;
                let round_signatures = signatures_by_round
                    .entry(round)
                    .or_insert_with(HashMap::new);
                round_signatures.insert(from.clone(), signature.clone());

                info!(
                    "💾 [SIGNING] Final node {} stored signature from {} for round {} (total: {})",
                    self.id,
                    from,
                    round,
                    round_signatures.len()
                );

                let should_agg = round_signatures.len() >= self.threshold;
                let signature_count = round_signatures.len();

                if should_agg {
                    info!(
                        "✅ [SIGNING] Enough signatures collected for round {}, will start aggregation",
                        round
                    );
                } else {
                    info!(
                        "⏳ [SIGNING] Waiting for more signatures for round {}: {}/{}",
                        round, signature_count, self.threshold
                    );
                }

                should_agg
            };

            if should_aggregate {
                // Get signatures for aggregation (outside the write lock)
                let signatures_to_aggregate = {
                    let signatures_by_round = self.signatures_by_round.read().await;
                    if let Some(round_signatures) = signatures_by_round.get(&round) {
                        round_signatures.clone()
                    } else {
                        HashMap::new()
                    }
                };

                // Perform aggregation
                match self
                    .aggregate_signatures_from_map(&signatures_to_aggregate)
                    .await
                {
                    Ok(_aggregated_signature) => {
                        info!("🎉 [SIGNING] Signature aggregation completed successfully for round {}!", round);
                        info!(
                            "📊 [SIGNING] Aggregated signature from {} nodes for round {}",
                            signatures_to_aggregate.len(),
                            round
                        );
                    }
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to aggregate signatures for round {}: {}",
                            round, e
                        );
                        return Err(e);
                    }
                }
            }
        } else {
            // If not the final node, proceed with normal signature completion check
            self.check_signature_completion(signature.message_hash)
                .await?;
        }

        Ok(())
    }

    async fn check_signature_completion(&self, message_hash: Vec<u8>) -> Result<()> {
        let signatures = self.signatures.read().await;
        if signatures.len() >= self.threshold {
            info!(
                "🎯 [SIGNING] Node {} has enough ECDSA signatures ({}), aggregating",
                self.id,
                signatures.len()
            );

            let aggregated_signature = self.aggregate_signatures().await?;

            info!(
                "Aggregated signature: {:?}",
                aggregated_signature.serialize_compact()
            );

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
                    aggregated_signature: aggregated_signature.serialize_compact().1.to_vec(),
                    signer_ids,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };

                let msg = serde_json::to_vec(&crate::types::GossipsubMessage::Signing(
                    SigningMessage::SignedMessage {
                        from: self.id.clone(),
                        signed_message: signed_message.clone(),
                    },
                ))?;

                self.broadcast("signing", &msg).await?;
                info!(
                    "🎉 [SIGNING] Node {} completed ECDSA signing and broadcasted result",
                    self.id
                );
                info!(
                    "📋 [SIGNING] Final aggregated signature: {:?}",
                    aggregated_signature
                );
            }
        } else {
            info!(
                "⏳ [SIGNING] Node {} waiting for more ECDSA signatures: {}/{}",
                self.id,
                signatures.len(),
                self.threshold
            );
        }
        Ok(())
    }

    async fn aggregate_signatures(&self) -> Result<RecoverableSignature> {
        let signatures = self.signatures.read().await;
        self.aggregate_signatures_from_map(&signatures).await
    }

    async fn aggregate_signatures_from_map(
        &self,
        signatures: &HashMap<String, ECDSASignature>,
    ) -> Result<RecoverableSignature> {
        if let Some((_, first_signature)) = signatures.iter().next() {
            let secp = Secp256k1::new();
            let recovery_id =
                secp256k1::ecdsa::RecoveryId::from_i32(first_signature.recovery_id as i32)?;
            let signature =
                RecoverableSignature::from_compact(&first_signature.signature, recovery_id)?;

            info!(
                "🔢 [SIGNING] Node {} using first ECDSA signature as aggregated result",
                self.id
            );
            Ok(signature)
        } else {
            Err(anyhow::anyhow!("No signatures to aggregate"))
        }
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

        info!("👥 [SIGNING] Signers: {:?}", signed_message.signer_ids);
        info!("🕒 [SIGNING] Timestamp: {}", signed_message.timestamp);

        // Verify the aggregated ECDSA signature
        let is_valid = self.verify_aggregated_signature(&signed_message).await?;
        if is_valid {
            info!("✅ [SIGNING] ECDSA signature verification successful!");
        } else {
            warn!("❌ [SIGNING] ECDSA signature verification failed!");
        }

        Ok(())
    }

    async fn verify_aggregated_signature(&self, signed_message: &SignedMessage) -> Result<bool> {
        info!(
            "🔍 [SIGNING] Node {} verifying aggregated signature",
            self.id
        );
        info!(
            "✍️ [SIGNING] Aggregated signature: {:?}",
            signed_message.aggregated_signature
        );
        info!("👥 [SIGNING] Signers: {:?}", signed_message.signer_ids);
        info!("🕒 [SIGNING] Timestamp: {}", signed_message.timestamp);

        let public_keys = self.public_keys.read().await;

        // Check if we have public keys for all signers
        for signer_id in &signed_message.signer_ids {
            if !public_keys.contains_key(signer_id) {
                warn!("❌ [SIGNING] Missing public key for signer: {}", signer_id);
                return Ok(false);
            }
        }

        info!("🔍 [SIGNING] Node {} verifying ECDSA signature", self.id);

        // For now, return true as a placeholder
        // In a real implementation, you'd verify each signature individually
        Ok(true)
    }

    /// Get the compressed 65-byte representation of an ECDSA signature
    pub fn get_compressed_signature_bytes(&self, signature: &RecoverableSignature) -> [u8; 65] {
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let mut result = [0u8; 65];
        result[0] = recovery_id.to_i32() as u8;
        result[1..].copy_from_slice(&signature_bytes);
        result
    }

    /// Get the compressed 65-byte representation as a hex string
    pub fn get_compressed_signature_hex(&self, signature: &RecoverableSignature) -> String {
        let bytes = self.get_compressed_signature_bytes(signature);
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

                    // Store the final node for this round
                    {
                        let mut final_nodes = self.final_nodes_by_round.write().await;
                        final_nodes.insert(round, result.final_node.0.to_string());
                        info!(
                            "💾 [CONSENSUS] Stored final node {} for round {}",
                            result.final_node.0, round
                        );
                    }

                    // Check if this node is the final selected node
                    if is_final_node {
                        info!(
                            "\x1b[32m🏆 [CONSENSUS] This node is the final selected node for round {}!\x1b[0m",
                            round
                        );
                        // Trigger aggregate signature for the final node
                        self.trigger_aggregate_signature_for_final_node(round)
                            .await?;

                        // Start collecting signatures after a short delay
                        let mut signing_node_clone = self.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                            if let Err(e) = signing_node_clone
                                .collect_and_aggregate_signatures(round)
                                .await
                            {
                                error!(
                                    "❌ [SIGNING] Failed to collect and aggregate signatures: {}",
                                    e
                                );
                            }
                        });
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

        // Broadcast a message to all nodes to send their signatures to the final node
        let signature_request = SigningMessage::RequestSignatures {
            round,
            final_node_id: self.id.clone(),
            message: "Aggregate signature request".to_string(),
        };

        // Wrap in GossipsubMessage::Signing for proper message handling
        let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_request);
        let broadcast_data = serde_json::to_vec(&gossipsub_msg)?;
        self.broadcast("signing", &broadcast_data).await?;

        info!(
            "📤 [SIGNING] Broadcasted signature request for round {} to all nodes",
            round
        );

        Ok(())
    }

    /// Send signature for specific round to the final selected node
    pub async fn send_signature_to_final_node(
        &mut self,
        final_node_id: &str,
        round: u64,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Sending signature for round {} to final node {}",
            round, final_node_id
        );

        // Get signature for this specific round
        let signatures_by_round = self.signatures_by_round.read().await;

        if let Some(round_signatures) = signatures_by_round.get(&round) {
            if let Some(our_signature) = round_signatures.get(&self.id) {
                let signature_msg = SigningMessage::ECDSASignature {
                    from: self.id.clone(),
                    signature: our_signature.clone(),
                };

                // Wrap in GossipsubMessage::Signing for proper message handling
                let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
                let signature_data = serde_json::to_vec(&gossipsub_msg)?;

                // Broadcast to a specific topic that the final node subscribes to
                self.broadcast("signatures-to-final-node", &signature_data)
                    .await?;

                info!(
                    "✅ [SIGNING] Sent signature for round {} to final node {}",
                    round, final_node_id
                );
            } else {
                info!(
                    "⚠️ [SIGNING] No signature found for round {} for this node",
                    round
                );
            }
        } else {
            info!("⚠️ [SIGNING] No signatures found for round {}", round);
        }

        Ok(())
    }

    /// Collect signatures and perform aggregation (for final selected node)
    pub async fn collect_and_aggregate_signatures(&mut self, round: u64) -> Result<()> {
        info!(
            "🔍 [SIGNING] Final node {} waiting for signatures for round {}",
            self.id, round
        );

        // Wait a bit for signatures to arrive
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Check current signature count for this round
        let signatures_by_round = self.signatures_by_round.read().await;
        if let Some(round_signatures) = signatures_by_round.get(&round) {
            info!(
                "📊 [SIGNING] Final node {} has {} signatures for round {}",
                self.id,
                round_signatures.len(),
                round
            );
        } else {
            info!("⚠️ [SIGNING] No signatures found for round {}", round);
        }

        Ok(())
    }

    /// Handle signature request from final selected node
    async fn handle_signature_request(
        &mut self,
        round: u64,
        final_node_id: String,
        _message: String,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Node {} responding to signature request for round {}",
            self.id, round
        );

        // Only send signature if we're not the final node
        if final_node_id != self.id {
            // Send signature to the final node
            self.send_signature_to_final_node(&final_node_id, round)
                .await?;
        } else {
            info!("🔄 [SIGNING] This node is the final node, no need to send signature to self");
        }

        Ok(())
    }

    /// Handle signature received by final node for specific round
    pub async fn handle_signature_for_round(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} for round {}",
            self.id, from, round
        );

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(from.clone(), signature.clone());

            info!(
                "💾 [SIGNING] Stored signature from {} for round {} (total: {})",
                from,
                round,
                round_signatures.len()
            );
        }

        // Check if we have enough signatures for this round
        let signatures_by_round = self.signatures_by_round.read().await;
        if let Some(round_signatures) = signatures_by_round.get(&round) {
            if round_signatures.len() >= self.threshold {
                info!(
                    "✅ [SIGNING] Enough signatures collected for round {}, starting aggregation",
                    round
                );

                // Perform aggregation
                match self.aggregate_signatures_from_map(round_signatures).await {
                    Ok(_aggregated_signature) => {
                        info!("🎉 [SIGNING] Signature aggregation completed successfully for round {}!", round);
                        info!(
                            "📊 [SIGNING] Aggregated signature from {} nodes for round {}",
                            round_signatures.len(),
                            round
                        );
                    }
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to aggregate signatures for round {}: {}",
                            round, e
                        );
                        return Err(e);
                    }
                }
            } else {
                info!(
                    "⏳ [SIGNING] Waiting for more signatures for round {}: {}/{}",
                    round,
                    round_signatures.len(),
                    self.threshold
                );
            }
        }

        Ok(())
    }

    /// Handle signature received on the signatures-to-final-node topic
    pub async fn handle_signature_to_final_node(
        &mut self,
        from: String,
        signature: ECDSASignature,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} on signatures-to-final-node topic",
            self.id, from
        );

        // Get the round from the final nodes by round map
        let round_to_handle = {
            let final_nodes = self.final_nodes_by_round.read().await;
            final_nodes.iter().find_map(|(round, final_node_id)| {
                if final_node_id == &self.id {
                    Some(*round)
                } else {
                    None
                }
            })
        };

        if let Some(round) = round_to_handle {
            return self
                .handle_signature_for_round(from, signature, round)
                .await;
        }

        info!("⚠️ [SIGNING] Received signature but this node is not the final node for any round");
        Ok(())
    }

    /// Get the node ID
    pub fn get_node_id(&self) -> &str {
        &self.id
    }
}
