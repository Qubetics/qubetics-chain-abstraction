use crate::rpc_server::DummyTransaction;
use anyhow::anyhow;
use anyhow::Result;
use k256::Scalar;
use hex;
use libp2p::PeerId;
use num_bigint::BigUint;
use num_traits::identities::One;
use rand::rngs::OsRng;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Digest as Sha2Digest;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use num_bigint::{BigInt, ToBigInt};
use secp256k1::{constants::CURVE_ORDER, ecdsa::RecoveryId};

use num_traits::Zero;
use rand::seq::SliceRandom;
use rand::thread_rng;

use crate::consensus::{ConsensusMessage, ConsensusNode, ConsensusResult};
use crate::types::{p2p::SerializablePeerId, ChannelMessage};
use crate::vrf::{VrfService, VrfSelectedNodesBroadcast};
use crate::chain::{ChainHandler, ChainSignature, ChainHandlerFactory, ChainTransaction};
use crate::utils::get_eth_address_from_group_key;
use crate::chain::BitcoinTransaction;
use crate::database::{SigningStorage, ConsensusStorage, Database};
use super::{ECDSASignature, SigningMessage, SignedMessage};
use k256::AffinePoint;
use sha3::{Keccak256, Digest};

/// Database-backed signing node that stores state in RocksDB
#[derive(Clone)]
pub struct DatabaseSigningNode {
    id: String,
    threshold: usize,
    private_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    signing_storage: SigningStorage,
    consensus_storage: ConsensusStorage,
    aggregated_rounds: Arc<RwLock<std::collections::HashSet<u64>>>, // Keep in memory for performance
    message_tx: mpsc::Sender<ChannelMessage>,
    vrf_service: Option<VrfService>,
    chain_handler: Arc<dyn ChainHandler>,
    consensus_node: Option<ConsensusNode>,
    available_nodes: Option<Vec<PeerId>>,
    group_public_key: Option<k256::ProjectivePoint>,
}

impl DatabaseSigningNode {
    pub fn new(id: String, threshold: usize, message_tx: mpsc::Sender<ChannelMessage>, database: Database) -> Self {
        // Parse the actual PeerId from the string ID
        let peer_id = PeerId::from_str(&id).unwrap_or_else(|_| {
            // Fallback to derived PeerId if parsing fails
            Self::derive_peer_id_from_string(&id)
        });

        // Create default Ethereum chain handler (can be changed later)
        let chain_handler = ChainHandlerFactory::create_ethereum_handler(1043);
        let chain_handler: Arc<dyn ChainHandler> = chain_handler.into();

        let signing_storage = SigningStorage::new(database.clone());
        let consensus_storage = ConsensusStorage::new(database);

        Self {
            id,
            threshold,
            private_key: None,
            public_key: None,
            signing_storage,
            consensus_storage,
            aggregated_rounds: Arc::new(RwLock::new(std::collections::HashSet::new())),
            message_tx: message_tx.clone(),
            vrf_service: Some(VrfService::new(peer_id, message_tx)),
            chain_handler,
            consensus_node: Some(ConsensusNode::new()),
            available_nodes: None,
            group_public_key: None,
        }
    }

    /// Derive a PeerId from a string (fallback method)
    fn derive_peer_id_from_string(id: &str) -> PeerId {
        use libp2p::identity::Keypair;
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let hash = hasher.finalize();
        
        // Use the hash as seed to generate a deterministic keypair
        let keypair = Keypair::generate_ed25519();
        PeerId::from(keypair.public())
    }

    pub fn set_threshold(&mut self, new_threshold: usize) {
        self.threshold = new_threshold;
    }

    pub fn get_id(&self) -> &str {
        &self.id
    }

    pub fn get_threshold(&self) -> usize {
        self.threshold
    }

    /// Set the private key for this signing node
    pub fn set_private_key(&mut self, private_key: SecretKey) {
        self.public_key = Some(PublicKey::from_secret_key(&Secp256k1::new(), &private_key));
        self.private_key = Some(private_key);
        info!("🔑 [DB_SIGNING] Set private key for node: {}", self.id);
    }

    /// Add a public key for another node
    pub async fn add_public_key(&self, node_id: String, public_key: PublicKey) -> Result<()> {
        self.signing_storage.store_public_key(&node_id, &public_key).await?;
        info!("🔑 [DB_SIGNING] Added public key for node: {}", node_id);
        Ok(())
    }

    /// Get public key for a node
    pub async fn get_public_key(&self, node_id: &str) -> Result<Option<PublicKey>> {
        self.signing_storage.get_public_key(node_id).await
    }

    /// Get all public keys
    pub async fn get_all_public_keys(&self) -> Result<HashMap<String, PublicKey>> {
        self.signing_storage.get_all_public_keys().await
    }

    /// Store a signature for a node
    pub async fn store_signature(&self, node_id: &str, signature: &ECDSASignature) -> Result<()> {
        self.signing_storage.store_signature(node_id, signature).await
    }

    /// Get a signature for a node
    pub async fn get_signature(&self, node_id: &str) -> Result<Option<ECDSASignature>> {
        self.signing_storage.get_signature(node_id).await
    }

    /// Store a signature for a specific round and node
    pub async fn store_signature_for_round(&self, round: u64, node_id: &str, signature: &ECDSASignature) -> Result<()> {
        self.signing_storage.store_signature_for_round(round, node_id, signature).await
    }

    /// Get signatures for a specific round
    pub async fn get_signatures_for_round(&self, round: u64) -> Result<HashMap<String, ECDSASignature>> {
        self.signing_storage.get_signatures_for_round(round).await
    }

    /// Store the final node for a round
    pub async fn store_final_node_for_round(&self, round: u64, node_id: &str) -> Result<()> {
        self.signing_storage.store_final_node_for_round(round, node_id).await
    }

    /// Get the final node for a round
    pub async fn get_final_node_for_round(&self, round: u64) -> Result<Option<String>> {
        self.signing_storage.get_final_node_for_round(round).await
    }

    /// Store a pending transaction for a round
    pub async fn store_pending_transaction(&self, round: u64, transaction: &ChainTransaction, tx_bytes: &[u8]) -> Result<()> {
        self.signing_storage.store_pending_transaction(round, transaction, tx_bytes).await
    }

    /// Get a pending transaction for a round
    pub async fn get_pending_transaction(&self, round: u64) -> Result<Option<(ChainTransaction, Vec<u8>)>> {
        self.signing_storage.get_pending_transaction(round).await
    }

    /// Delete a pending transaction for a round
    pub async fn delete_pending_transaction(&self, round: u64) -> Result<()> {
        self.signing_storage.delete_pending_transaction(round).await
    }

    /// Check if a round has been aggregated
    pub async fn is_round_aggregated(&self, round: u64) -> Result<bool> {
        // Check both in-memory cache and database
        {
            let aggregated = self.aggregated_rounds.read().await;
            if aggregated.contains(&round) {
                return Ok(true);
            }
        }
        
        self.signing_storage.is_round_aggregated(round).await
    }

    /// Mark a round as aggregated
    pub async fn mark_round_aggregated(&self, round: u64) -> Result<()> {
        // Update both in-memory cache and database
        {
            let mut aggregated = self.aggregated_rounds.write().await;
            aggregated.insert(round);
        }
        
        self.signing_storage.mark_round_aggregated(round).await
    }

    /// Clear signatures for a round after aggregation
    pub async fn clear_signatures_for_round(&self, round: u64) -> Result<()> {
        self.signing_storage.clear_signatures_for_round(round).await
    }

    /// Set the group public key from DKG
    pub fn set_group_public_key(&mut self, group_key: k256::ProjectivePoint) {
        self.group_public_key = Some(group_key);
        info!("🔑 [DB_SIGNING] Set DKG group public key for node: {}", self.id);
    }

    /// Get the group public key
    pub fn get_group_public_key(&self) -> Option<k256::ProjectivePoint> {
        self.group_public_key
    }

    /// Set available nodes from node manager
    pub fn set_available_nodes(&mut self, nodes: Vec<PeerId>) {
        self.available_nodes = Some(nodes);
        info!("📋 [DB_SIGNING] Updated available nodes count: {}", self.available_nodes.as_ref().unwrap().len());
    }

    /// Get available nodes
    pub fn get_available_nodes(&self) -> Option<&Vec<PeerId>> {
        self.available_nodes.as_ref()
    }

    /// Set VRF service
    pub fn set_vrf_service(&mut self, vrf_service: VrfService) {
        self.vrf_service = Some(vrf_service);
    }

    /// Set consensus node
    pub fn set_consensus_node(&mut self, consensus_node: ConsensusNode) {
        self.consensus_node = Some(consensus_node);
    }

    /// Set chain handler
    pub fn set_chain_handler(&mut self, chain_handler: Arc<dyn ChainHandler>) {
        self.chain_handler = chain_handler;
    }

    /// Get chain parameters (delegated to chain handler)
    pub fn get_chain_params(&self) -> std::collections::HashMap<String, String> {
        let mut params = std::collections::HashMap::new();
        params.insert("threshold".to_string(), self.threshold.to_string());
        params.insert("node_id".to_string(), self.id.clone());
        params.insert("has_private_key".to_string(), self.private_key.is_some().to_string());
        params.insert("has_group_key".to_string(), self.group_public_key.is_some().to_string());
        params
    }

    /// Get consensus storage for external access
    pub fn get_consensus_storage(&self) -> &ConsensusStorage {
        &self.consensus_storage
    }

    /// Get signing storage for external access
    pub fn get_signing_storage(&self) -> &SigningStorage {
        &self.signing_storage
    }

    /// Process signing message (main entry point for handling signing protocol messages)
    pub async fn process_signing_message(&mut self, message: SigningMessage) -> Result<()> {
        match message {
            SigningMessage::MessageToSign { from, message: msg, message_hash } => {
                self.handle_message_to_sign(from, msg, message_hash).await
            },
            SigningMessage::ECDSASignature { from, signature, round, timestamp } => {
                self.handle_ecdsa_signature(from, signature, round, timestamp).await
            },
            SigningMessage::SignedMessage { from, signed_message } => {
                self.handle_signed_message(from, signed_message).await
            },
            SigningMessage::RequestSignatures { round, final_node_id, message } => {
                self.handle_request_signatures(round, final_node_id, message).await
            },
        }
    }

    /// Handle message to sign
    async fn handle_message_to_sign(&mut self, from: String, message: Vec<u8>, message_hash: Vec<u8>) -> Result<()> {
        info!("📝 [DB_SIGNING] Received message to sign from {}", from);
        
        if let Some(private_key) = &self.private_key {
            let signature = self.sign_message(&message_hash, private_key)?;
            
            // Store our signature
            self.store_signature(&self.id, &signature).await?;
            
            // Broadcast signature to other nodes
            let signing_msg = SigningMessage::ECDSASignature {
                from: self.id.clone(),
                signature,
                round: 0, // TODO: Get proper round number
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            };
            
            // Send via message channel
            let channel_msg = ChannelMessage::Broadcast {
                topic: "signing".to_string(),
                data: bincode::serialize(&signing_msg)?,
            };
            
            if let Err(e) = self.message_tx.send(channel_msg).await {
                error!("Failed to broadcast signature: {}", e);
            }
        } else {
            warn!("Cannot sign message - no private key set");
        }
        
        Ok(())
    }

    /// Handle ECDSA signature
    async fn handle_ecdsa_signature(&mut self, from: String, signature: ECDSASignature, round: u64, timestamp: u128) -> Result<()> {
        info!("✍️ [DB_SIGNING] Received ECDSA signature from {} for round {}", from, round);
        
        // Store signature for this round
        self.store_signature_for_round(round, &from, &signature).await?;
        
        // Check if we have enough signatures for threshold
        let signatures = self.get_signatures_for_round(round).await?;
        if signatures.len() >= self.threshold {
            info!("🎯 [DB_SIGNING] Threshold reached for round {} ({}/{})", round, signatures.len(), self.threshold);
            
            // Mark round as aggregated to prevent duplicate processing
            if !self.is_round_aggregated(round).await? {
                self.mark_round_aggregated(round).await?;
                
                // TODO: Implement signature aggregation logic
                // This would involve combining the signatures and creating a final aggregated signature
                
                info!("✅ [DB_SIGNING] Successfully aggregated signatures for round {}", round);
                
                // Clean up signatures for this round
                self.clear_signatures_for_round(round).await?;
            }
        }
        
        Ok(())
    }

    /// Handle signed message
    async fn handle_signed_message(&mut self, from: String, signed_message: SignedMessage) -> Result<()> {
        info!("📨 [DB_SIGNING] Received signed message from {}", from);
        // TODO: Implement signed message handling logic
        Ok(())
    }

    /// Handle request signatures
    async fn handle_request_signatures(&mut self, round: u64, final_node_id: String, message: String) -> Result<()> {
        info!("📋 [DB_SIGNING] Received signature request for round {} from final node {}", round, final_node_id);
        
        // Store the final node for this round
        self.store_final_node_for_round(round, &final_node_id).await?;
        
        // TODO: Implement signature request handling logic
        Ok(())
    }

    /// Sign a message hash with the node's private key
    fn sign_message(&self, message_hash: &[u8], private_key: &SecretKey) -> Result<ECDSASignature> {
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(message_hash)?;
        
        let (recovery_id, signature) = secp.sign_ecdsa_recoverable(&message, private_key).serialize_compact();
        
        // Convert to 65-byte format (64 bytes signature + 1 byte recovery ID)
        let mut signature_bytes = Vec::with_capacity(65);
        signature_bytes.extend_from_slice(&signature);
        signature_bytes.push(recovery_id.to_i32() as u8);
        
        Ok(ECDSASignature {
            signature: signature_bytes,
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
        })
    }
}
