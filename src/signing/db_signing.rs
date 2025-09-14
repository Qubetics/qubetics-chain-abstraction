use anyhow::{anyhow, Result};
use libp2p::PeerId;
use std::str::FromStr;
use secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::info;

use super::ECDSASignature;
use crate::chain::{ChainHandler, ChainHandlerFactory, ChainTransaction};
use crate::consensus::ConsensusNode;
use crate::contract::{ContractClient, ContractConfig, SolverManagerContract};
use crate::database::{key_utils, ConsensusStorage, Database, SigningStorage};
use crate::types::ChannelMessage;
use crate::vrf::VrfService;

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
    pub vrf_service: Option<VrfService>,
    chain_handler: Arc<dyn ChainHandler>,
    consensus_node: Option<ConsensusNode>,
    available_nodes: Option<Vec<PeerId>>,
    group_public_key: Option<k256::ProjectivePoint>,
}

impl DatabaseSigningNode {
    pub fn new(
        id: String,
        threshold: usize,
        message_tx: mpsc::Sender<ChannelMessage>,
        database: Database,
    ) -> Self {
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
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let _hash = hasher.finalize();
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
        self.signing_storage
            .store_public_key(&node_id, &public_key)
            .await?;
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
        self.signing_storage
            .store_signature(node_id, signature)
            .await
    }

    /// Get a signature for a node
    pub async fn get_signature(&self, node_id: &str) -> Result<Option<ECDSASignature>> {
        self.signing_storage.get_signature(node_id).await
    }

    /// Store a signature for a specific round and node
    pub async fn store_signature_for_round(
        &self,
        round: u64,
        node_id: &str,
        signature: &ECDSASignature,
    ) -> Result<()> {
        self.signing_storage
            .store_signature_for_round(round, node_id, signature)
            .await
    }

    /// Get signatures for a specific round
    pub async fn get_signatures_for_round(
        &self,
        round: u64,
    ) -> Result<HashMap<String, ECDSASignature>> {
        self.signing_storage.get_signatures_for_round(round).await
    }

    /// Store the final node for a round
    pub async fn store_final_node_for_round(&self, round: u64, node_id: &str) -> Result<()> {
        self.signing_storage
            .store_final_node_for_round(round, node_id)
            .await
    }

    /// Get the final node for a round
    pub async fn get_final_node_for_round(&self, round: u64) -> Result<Option<String>> {
        self.signing_storage.get_final_node_for_round(round).await
    }

    /// Store a pending transaction for a round
    pub async fn store_pending_transaction(
        &self,
        round: u64,
        transaction: &ChainTransaction,
        tx_bytes: &[u8],
    ) -> Result<()> {
        self.signing_storage
            .store_pending_transaction(round, transaction, tx_bytes)
            .await
    }

    /// Get a pending transaction for a round
    pub async fn get_pending_transaction(
        &self,
        round: u64,
    ) -> Result<Option<(ChainTransaction, Vec<u8>)>> {
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
        info!(
            "🔑 [DB_SIGNING] Set DKG group public key for node: {}",
            self.id
        );
    }

    /// Get the group public key
    pub fn get_group_public_key(&self) -> Option<k256::ProjectivePoint> {
        self.group_public_key
    }

    /// Set available nodes from node manager
    pub fn set_available_nodes(&mut self, nodes: Vec<PeerId>) {
        self.available_nodes = Some(nodes);
        info!(
            "📋 [DB_SIGNING] Updated available nodes count: {}",
            self.available_nodes.as_ref().unwrap().len()
        );
    }

    /// Get available nodes
    pub fn get_available_nodes(&self) -> Option<&Vec<PeerId>> {
        self.available_nodes.as_ref()
    }

    /// Set VRF service
    pub fn set_vrf_service(&mut self, vrf_service: VrfService) {
        self.vrf_service = Some(vrf_service);
    }

    /// Initialize VrfService with network round synchronization
    /// This should be called only after the node has connected to the network
    /// and received round information from other nodes
    pub async fn initialize_vrf_service_with_network_sync(&mut self, network_round: Option<u64>) {
        if self.vrf_service.is_some() {
            info!("🔄 [DB_SIGNING] VrfService already initialized for node {}", self.id);
            return;
        }

        let peer_id = PeerId::from_str(&self.id).unwrap_or_else(|_| PeerId::random());
        
        // Create VrfService with proper initial round
        let mut vrf_service = VrfService::new(peer_id, self.message_tx.clone());
        
        // Set the current round to match the network
        if let Some(network_round) = network_round {
            vrf_service.set_current_round(network_round).await;
            info!("🔄 [DB_SIGNING] Initialized VrfService for node {} with network round: {}", self.id, network_round);
        } else {
            info!("🆕 [DB_SIGNING] Initialized VrfService for node {} with default round: 0 (first node)", self.id);
        }
        
        self.vrf_service = Some(vrf_service);
    }

    /// Sync VRF round with network (simple approach)
    pub async fn sync_vrf_round_with_network(&mut self, network_round: u64) {
        if let Some(vrf_service) = &mut self.vrf_service {
            vrf_service.set_current_round(network_round).await;
            info!("🔄 [DB_SIGNING] Synced VRF round to: {}", network_round);
        }
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
        params.insert(
            "has_private_key".to_string(),
            self.private_key.is_some().to_string(),
        );
        params.insert(
            "has_group_key".to_string(),
            self.group_public_key.is_some().to_string(),
        );
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
}
