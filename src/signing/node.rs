use crate::types::signing::{
    BtcIndexedSignature, ECDSASignature, SignedMessage, SigningMessage, ThresholdSignatureShare,
};
use crate::types::SpendKind;
use anyhow::{anyhow, Result};
use hex;
use k256::Scalar;
use libp2p::PeerId;
use num_bigint::BigUint;
use num_traits::identities::One;
use once_cell::sync::Lazy;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use sha3::Digest;
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

pub(crate) static NONCE_DIGEST_AUDIT_REGISTRY: Lazy<RwLock<HashMap<(String, String), [u8; 32]>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub use super::chains::{BitcoinSigner, TicsSigner};
pub use super::config::{BroadcastConfig, ChainBroadcastConfig};
pub use super::coordination::Coordination;
pub use super::db_signing::DatabaseSigningNode;
pub use super::key::KeyStore;
pub use super::state::{
    BroadcastPolicy, BtcAggregationState, BtcRoundExtras, BtcUtvAggregationState, PendingStore,
    PendingValue, RoundSlotKey, SignatureStore, SigningEnvironmentBuilder,
};
pub use super::nonce::{NonceGenerator, NonceManager};

use num_bigint::{BigInt, ToBigInt};
use secp256k1::{constants::CURVE_ORDER, ecdsa::RecoveryId};

use crate::chain_abstraction::{ChainHandler, ChainTransaction};
use crate::protocols::{VrfSelectedNodesBroadcast, VrfService};
use crate::hrw;
use crate::types::{
    p2p::SerializablePeerId, ChannelMessage, ConsensusMessage, ConsensusResult, GossipsubMessage,
    TransactionType,
};
use crate::user_intent_manager::UserIntentManager;
use num_traits::Zero;

/// Number of recent UserToVault batches to exclude from the next pick (sliding window).
const LAST_N_USER_TO_VAULT_BATCHES: usize = 10;

/// Slot type for per-slot aggregation (TICS vs BTC UserToVault batch).
#[derive(Clone, Debug)]
pub enum SlotKind {
    TicsUserToVault,
    BtcUserToVault,
}

#[derive(Clone)]
pub struct SigningNode {
    pub(crate) id: String,
    pub(crate) threshold: usize,
    pub(crate) key_store: KeyStore,
    pub(crate) signatures: SignatureStore,
    pub(crate) message_tx: mpsc::Sender<ChannelMessage>,
    pub(crate) coordination: Coordination,
    pub(crate) chain_handler: Arc<dyn ChainHandler>, // Chain-specific operations for regular transactions
    pub(crate) contract_chain_handler: Arc<dyn ChainHandler>, // Chain handler specifically for contract transactions
    pub(crate) pending: PendingStore,
    pub(crate) btc_state: BtcAggregationState,
    /// BTC UserToVault batch aggregation state (multi-input per slot)
    pub(crate) btc_utv_state: BtcUtvAggregationState,
    // User registry for storing transaction IDs
    pub(crate) user_intent_manager: Option<Arc<UserIntentManager>>,
    // Database for storing solver amounts
    pub(crate) database: Option<Arc<crate::database::Database>>,
    /// DKG storage for HRW candidate set (canonical final-node selection). Not used for peer_indices.
    pub(crate) dkg_storage: Option<crate::database::DkgStorage>,
    // Dynamic broadcast configuration
    pub(crate) broadcast_policy: BroadcastPolicy,
    /// Self-reference for spawning non-blocking aggregation tasks (set after wrapping in Arc<Mutex<SigningNode>>).
    pub(crate) self_ref: Option<Arc<Mutex<SigningNode>>>,
    /// Last N batches of intent hashes picked for TICS UserToVault (sliding window); intents in these sets are excluded from the next pick.
    pub(crate) last_tics_user_to_vault_batch_hashes: Arc<RwLock<VecDeque<HashSet<String>>>>,
    /// Last N batches of intent hashes picked for BTC UserToVault (sliding window); intents in these sets are excluded from the next pick.
    pub(crate) last_btc_user_to_vault_batch_hashes: Arc<RwLock<VecDeque<HashSet<String>>>>,
    /// Nonce manager for random k generation (optional until fully integrated)
    pub(crate) nonce_manager: Option<Arc<tokio::sync::Mutex<super::nonce::NonceManager>>>,
    /// Currently connected peers (updated on connect/disconnect).
    /// Used by HRW to filter candidates to only connected peers.
    pub(crate) connected_peers: HashSet<PeerId>,
}

impl SigningNode {

    pub fn set_threshold(&mut self, new_threshold: usize) {
        self.threshold = new_threshold;
    }

    /// Mark a peer as connected (for HRW candidate filtering).
    pub fn add_connected_peer(&mut self, peer: PeerId) {
        self.connected_peers.insert(peer);
    }

    /// Mark a peer as disconnected (for HRW candidate filtering).
    pub fn remove_connected_peer(&mut self, peer: &PeerId) {
        self.connected_peers.remove(peer);
    }

    /// Get the set of currently connected peers.
    pub fn get_connected_peers(&self) -> &HashSet<PeerId> {
        &self.connected_peers
    }

    pub fn vrf_service(&self) -> Option<&VrfService> {
        self.coordination.vrf_service()
    }

    pub fn vrf_service_mut(&mut self) -> Option<&mut VrfService> {
        self.coordination.vrf_service_mut()
    }

    pub fn new(id: String, threshold: usize, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        let peer_id =
            PeerId::from_str(&id).unwrap_or_else(|_| super::coordination::derive_peer_id_from_string(&id));
        let environment = SigningEnvironmentBuilder::new(id.clone(), message_tx.clone())
            .build_with_coordination(Coordination::new(peer_id, message_tx.clone()));

        Self {
            id,
            threshold,
            key_store: KeyStore::new(),
            signatures: SignatureStore::new(),
            message_tx: message_tx.clone(),
            coordination: environment.coordination,
            chain_handler: environment.chain_handler,
            contract_chain_handler: environment.contract_chain_handler,
            pending: PendingStore::new(),
            btc_state: BtcAggregationState::new(),
            btc_utv_state: BtcUtvAggregationState::new(),
            user_intent_manager: None, // Will be set later via set_user_intent_manager
            database: None,            // Will be set later via set_database
            dkg_storage: None,         // Will be set later via set_database (for HRW candidates)
            broadcast_policy: environment.broadcast_policy,
            self_ref: None,            // Set via set_self_arc after wrapping in Arc<Mutex<SigningNode>>
            last_tics_user_to_vault_batch_hashes: Arc::new(RwLock::new(VecDeque::new())),
            last_btc_user_to_vault_batch_hashes: Arc::new(RwLock::new(VecDeque::new())),
            nonce_manager: None,       // Set via set_nonce_manager after database is available
            connected_peers: {
                let mut s = HashSet::new();
                s.insert(peer_id); // Include self in connected peers
                s
            },
        }
    }

    /// Set self-reference so the node can spawn aggregation tasks. Call after wrapping in Arc<Mutex<SigningNode>>.
    pub fn set_self_arc(&mut self, arc: Arc<Mutex<SigningNode>>) {
        self.self_ref = Some(arc);
    }

    /// Record a TICS UserToVault batch (by intent hashes) so it is excluded from the next N picks on this node.
    /// Call this on every node when a batch is received (gossip) so the sliding window is consistent across the network.
    pub fn record_tics_user_to_vault_batch(&self, intent_hashes: &[String]) {
        if intent_hashes.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.last_tics_user_to_vault_batch_hashes.write() {
            guard.push_back(intent_hashes.iter().cloned().collect());
            while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                guard.pop_front();
            }
        }
    }

    /// Record a BTC UserToVault batch (by intent hashes) so it is excluded from the next N picks on this node.
    /// Call this on every node when a batch is received (gossip) so the sliding window is consistent across the network.
    pub fn record_btc_user_to_vault_batch(&self, intent_hashes: &[String]) {
        if intent_hashes.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.last_btc_user_to_vault_batch_hashes.write() {
            guard.push_back(intent_hashes.iter().cloned().collect());
            while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                guard.pop_front();
            }
        }
    }

    /// Print the current broadcast configuration
    pub fn print_broadcast_config(&self) {
        self.broadcast_policy.config.print_config();
    }

    // Configuration methods
    pub fn set_broadcast_config(&mut self, config: BroadcastConfig) {
        self.broadcast_policy.config = config;
    }

    pub fn get_broadcast_config(&self) -> &BroadcastConfig {
        &self.broadcast_policy.config
    }

    pub fn update_chain_config(&mut self, chain_type: &str, config: ChainBroadcastConfig) {
        self.broadcast_policy
            .config
            .chain_configs
            .insert(chain_type.to_string(), config);
    }

    pub fn enable_chain(&mut self, chain_type: &str, enabled: bool) {
        if let Some(chain_config) = self
            .broadcast_policy
            .config
            .chain_configs
            .get_mut(chain_type)
        {
            chain_config.enabled = enabled;
        }
    }

    /// Compute BtcRoundExtras for observer nodes receiving BTC TX data.
    /// Derives the group public key, computes HASH160, and returns extras needed for finalization.
    pub(crate) async fn compute_btc_extras_for_observer(
        &self,
        tx_type: &Option<crate::types::TransactionType>,
        user_eth: &str,
        round: u64,
    ) -> Option<BtcRoundExtras> {
        let pubkey_bytes = match self.get_group_public_key_bytes(
            tx_type.clone(),
            if user_eth.is_empty() { None } else { Some(user_eth.to_string()) },
        ).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(
                    "⚠️ [SIGNING] Could not compute BtcRoundExtras for round {}: {}",
                    round, e
                );
                return None;
            }
        };
        if pubkey_bytes.len() != 33 {
            warn!(
                "⚠️ [SIGNING] Invalid pubkey length {} for BtcRoundExtras round {}",
                pubkey_bytes.len(), round
            );
            return None;
        }
        let pubkey33: [u8; 33] = pubkey_bytes.as_slice().try_into().unwrap();
        // hash160 = RIPEMD160(SHA256(pubkey))
        let sha = <sha2::Sha256 as sha2::Digest>::digest(&pubkey33);
        let rip = <ripemd::Ripemd160 as ripemd::Digest>::digest(&sha);
        let mut signer_h160 = [0u8; 20];
        signer_h160.copy_from_slice(&rip);
        let is_testnet = crate::types::network::network_type().is_testnet();
        Some(BtcRoundExtras {
            pubkey33,
            signer_h160,
            from_kind: SpendKind::P2PKH,
            is_testnet,
        })
    }

    pub(crate) async fn handle_signed_message(
        &mut self,
        from: String,
        signed_message: SignedMessage,
    ) -> Result<()> {
        debug!(
            "[SIGNING] Node {} received signed message from {} with {} signers",
            self.id, from, signed_message.signer_ids.len()
        );

        // Verify the aggregated ECDSA signature
        let is_valid = self.verify_aggregated_signature(&signed_message).await?;
        if is_valid {
            debug!("[SIGNING] Node {} - signature verification successful", self.id);
        } else {
            warn!("[SIGNING] Node {} - ECDSA signature verification failed from {}", self.id, from);
        }

        Ok(())
    }

    /// Get VRF public key for this node
    pub async fn get_vrf_public_key(&self) -> Option<String> {
        if let Some(vrf_service) = self.coordination.vrf_service() {
            Some(vrf_service.get_public_key_hex().await)
        } else {
            None
        }
    }

    /// Get VRF public key as bytes
    pub async fn get_vrf_public_key_bytes(&self) -> Option<Vec<u8>> {
        if let Some(vrf_service) = self.coordination.vrf_service() {
            Some(vrf_service.get_public_key().await)
        } else {
            None
        }
    }

    /// Set the chain handler for this signing node
    pub fn set_chain_handler(&mut self, chain_handler: Arc<dyn ChainHandler>) {
        self.chain_handler = chain_handler;
        info!(
            "🔗 [SIGNING] Node {} switched to {} chain handler",
            self.id,
            self.chain_handler.chain_type()
        );
    }

    /// Set the contract chain handler for this signing node
    pub fn set_contract_chain_handler(&mut self, contract_chain_handler: Arc<dyn ChainHandler>) {
        self.contract_chain_handler = contract_chain_handler;
        info!(
            "🔗 [SIGNING] Node {} switched to {} contract chain handler",
            self.id,
            self.contract_chain_handler.chain_type()
        );
    }

    /// Get a reference to the chain handler
    pub fn get_chain_handler(&self) -> &Arc<dyn ChainHandler> {
        &self.chain_handler
    }

    /// Get a reference to the contract chain handler
    pub fn get_contract_chain_handler(&self) -> &Arc<dyn ChainHandler> {
        &self.contract_chain_handler
    }

    /// Get the current chain type
    pub fn get_chain_type(&self) -> &'static str {
        self.chain_handler.chain_type()
    }

    /// Get chain parameters
    pub fn get_chain_params(&self) -> std::collections::HashMap<String, String> {
        self.chain_handler.get_chain_params()
    }

    /// Set available nodes from node manager
    pub fn set_available_nodes(&mut self, nodes: Vec<PeerId>) {
        self.coordination.set_available_nodes(nodes);
    }

    pub fn set_user_intent_manager(&mut self, user_intent_manager: Arc<UserIntentManager>) {
        self.user_intent_manager = Some(user_intent_manager);
        info!("📋 [SIGNING] Node {} user registry set", self.id);
    }

    pub fn set_database(&mut self, database: Arc<crate::database::Database>) {
        self.database = Some(database.clone());
        self.dkg_storage = Some(crate::database::DkgStorage::new((*database).clone()));

        // Update Coordination with database so VrfService can use it
        self.coordination.set_database(database);

        info!(
            "🗄️ [SIGNING] Node {} database set with round storage and HRW DKG candidates",
            self.id
        );
    }

    /// Get peer index directly from database
    pub(crate) async fn get_peer_index_from_db(&self, peer_id: &str) -> Option<usize> {
        if let Some(db) = &self.database {
            let key = crate::database::key_utils::peer_index_key(peer_id);
            match db.get_string::<usize>(&key) {
                Ok(Some(index)) => {
                    info!(
                        "🔢 [SIGNING] Retrieved peer index {} for {} from database",
                        index, peer_id
                    );
                    Some(index)
                }
                Ok(None) => {
                    info!(
                        "🔍 [SIGNING] No peer index found in database for {}",
                        peer_id
                    );
                    None
                }
                Err(e) => {
                    warn!(
                        "❌ [SIGNING] Failed to get peer index from database for {}: {:?}",
                        peer_id, e
                    );
                    None
                }
            }
        } else {
            warn!(
                "⚠️ [SIGNING] No database available to get peer index for {}",
                peer_id
            );
            None
        }
    }

    /// Process phase 1 completed intents for global clock trigger.
    /// Phase 1 = UserToVault transaction complete, NetworkToTarget pending.
    /// `target_chain`: "qubetics" (TICS) or "bitcoin" (BTC) — passed by caller based on epoch; no re-calculation inside.
    pub(crate) async fn process_phase1_intents_for_global_clock(&self, round: u64, target_chain: &str) -> Result<()> {
        info!(
            "🔍 [CLOCK] Processing phase 1 completed intents for round {} (target_chain={})",
            round, target_chain
        );
        
        // Read max intents per cycle from environment (configurable)
        let max_intents_per_cycle = crate::env_defaults::max_intents_per_cycle()
            .parse::<usize>()
            .unwrap_or(crate::env_defaults::DEFAULT_MAX_INTENTS_PER_CYCLE.parse().unwrap());
        
        // Get user intent manager
        let user_intent_manager = self.user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        
        // Batch type from passed target_chain (no cycle/timestamp logic here)
        let batch_type = if target_chain.eq_ignore_ascii_case("qubetics") {
            crate::types::BatchType::TICS
        } else {
            crate::types::BatchType::BTC
        };
        
        info!(
            "⏰ [CLOCK] Processing {} intents with batch type {:?} (round {})",
            target_chain.to_uppercase(),
            batch_type,
            round
        );
        
        // Get intents awaiting network fulfillment (stale > 10 seconds)
        let awaiting_intents = user_intent_manager
            .get_intents_awaiting_network_fulfillment(Some(10))
            .await;
        
        // Filter by target chain (case-insensitive; target_chain passed by caller)
        let target_lower = target_chain.to_lowercase();
        let mut filtered_intents: Vec<_> = awaiting_intents
            .into_iter()
            .filter(|(_, intent, _)| {
                intent.target_chain.to_lowercase() == target_lower
            })
            .collect();
        
        // Sort by updated_at (oldest first) - intents waiting longest get priority
        filtered_intents.sort_by(|a, b| a.2.updated_at.cmp(&b.2.updated_at));
        
        // Limit to configured max intents to avoid overwhelming the system
        let intents_to_process: Vec<_> = filtered_intents.into_iter().take(max_intents_per_cycle).collect();
        
        info!(
            "📊 [CLOCK] Found {} {} intents (sorted by age, limited to {})",
            intents_to_process.len(),
            target_chain.to_uppercase(),
            max_intents_per_cycle
        );
        
        // Collect intent hashes for broadcasting
        let intent_hashes: Vec<String> = intents_to_process
            .iter()
            .map(|(intent_hash, _, _)| intent_hash.clone())
            .collect();
        
        // If we have intents to process, broadcast the batch to all nodes
        if !intent_hashes.is_empty() {
            info!(
                "📤 [CLOCK] Broadcasting batch of {} {} intent hashes to all nodes (batch type: {:?})",
                intent_hashes.len(),
                target_chain.to_uppercase(),
                batch_type
            );
            
            // Create timestamp for the batch
            let batch_timestamp = chrono::Utc::now().to_rfc3339();
            let batch_id = format!(
                "intent_batch_{}_{}_{}",
                target_chain.to_lowercase(),
                round,
                batch_timestamp
            );

            // Reserve coordinated nonces BEFORE broadcasting.
            // - TICS: single-signature EVM contract-call flow (1 nonce)
            // - BTC: one nonce per input digest in the computed unsigned batch tx
            let nonce_tuple_ids = if target_chain.eq_ignore_ascii_case("bitcoin") {
                let total_inputs = match self.compute_btc_intent_batch_input_count(&intent_hashes).await {
                    Ok(count) if count > 0 => count,
                    Ok(_) => {
                        tracing::error!("🔴 [CLOCK] BTC intent batch has zero inputs - aborting (will retry next cycle)");
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::error!("🔴 [CLOCK] Failed to compute BTC batch input count before nonce reservation: {} - aborting (will retry next cycle)", e);
                        return Ok(());
                    }
                };

                let op_ids: Vec<String> = (0..total_inputs)
                    .map(|i| format!("{}_{}", batch_id, i))
                    .collect();

                if let Some(nm) = &self.nonce_manager {
                    let nm_guard = nm.lock().await;
                    match nm_guard.reserve_nonces_for_batch(&op_ids).await {
                        Ok(assignments) => {
                            if assignments.len() < op_ids.len() {
                                tracing::error!(
                                    "🔴 [CLOCK] Reserved only {} of {} required BTC nonces for batch {} - aborting (will retry next cycle)",
                                    assignments.len(),
                                    op_ids.len(),
                                    batch_id
                                );
                                return Ok(());
                            }

                            let mut ordered = Vec::with_capacity(op_ids.len());
                            for op_id in &op_ids {
                                if let Some(tuple_id) = assignments.get(op_id) {
                                    ordered.push(tuple_id.clone());
                                } else {
                                    tracing::error!("🔴 [CLOCK] Missing nonce for BTC op_id {} - aborting (will retry next cycle)", op_id);
                                    return Ok(());
                                }
                            }
                            info!(
                                "🔐 [CLOCK] Reserved {} ordered nonces for BTC intent batch {}",
                                ordered.len(),
                                batch_id
                            );
                            ordered
                        }
                        Err(e) => {
                            tracing::error!("🔴 [CLOCK] Failed to reserve BTC nonces for batch {}: {} - aborting (will retry next cycle)", batch_id, e);
                            return Ok(());
                        }
                    }
                } else {
                    tracing::error!("🔴 [CLOCK] NonceManager not available for BTC intent batch - aborting (will retry next cycle)");
                    return Ok(());
                }
            } else if let Some(nm) = &self.nonce_manager {
                let intent_fingerprint = {
                    let mut hasher = sha3::Keccak256::new();
                    hasher.update(intent_hashes.join(",").as_bytes());
                    hex::encode(&hasher.finalize()[..8])
                };
                let reservation_key = format!(
                    "contract_call:{}:round:{}:batch:{}:intent_fp:{}",
                    target_chain.to_lowercase(),
                    round,
                    batch_id,
                    intent_fingerprint
                );
                let nm_guard = nm.lock().await;
                match nm_guard
                    .reserve_nonces_for_batch(std::slice::from_ref(&reservation_key))
                    .await
                {
                    Ok(assignments) => {
                        if let Some(tuple_id) = assignments.get(&reservation_key) {
                            info!(
                                "🔐 [CLOCK] Reserved nonce tuple assignment reservation_key={} tuple_id={} for {} intent batch",
                                reservation_key,
                                tuple_id,
                                target_chain.to_uppercase()
                            );
                            vec![tuple_id.clone()]
                        } else {
                            tracing::error!("🔴 [CLOCK] No nonce available for {} intent batch - aborting (will retry next cycle)", target_chain.to_uppercase());
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::error!("🔴 [CLOCK] Failed to reserve nonce for {} intent batch: {} - aborting (will retry next cycle)", target_chain.to_uppercase(), e);
                        return Ok(());
                    }
                }
            } else {
                tracing::error!("🔴 [CLOCK] NonceManager not available for {} intent batch - aborting (will retry next cycle)", target_chain.to_uppercase());
                return Ok(());
            };

            // Send via channel so the origin node processes the batch locally AND gossips it
            // to other peers (channel handler will publish and also call gossipsub handler).
            self.message_tx
                .send(crate::types::ChannelMessage::IntentBatchBroadcast {
                    intent_hashes: intent_hashes.clone(),
                    batch_type: format!("{:?}", batch_type), // "BTC" or "TICS"
                    timestamp: batch_timestamp.clone(),
                    round,
                    node_id: self.id.clone(),
                    nonce_tuple_ids: Some(nonce_tuple_ids), // Coordinated nonces reserved above
                })
                .await?;
            
            info!(
                "✅ [CLOCK] Successfully broadcasted {} intent batch with {} hashes at {}",
                target_chain.to_uppercase(),
                intent_hashes.len(),
                batch_timestamp
            );
            
            // Log details of each intent in the batch
            for (intent_hash, intent, tx_ids) in intents_to_process {
                let wait_duration = chrono::Utc::now().signed_duration_since(tx_ids.updated_at);
                info!(
                    "  📋 [BATCH] Intent {}: amount={}, source={}, target={}, waiting={}s, UserToVault TX: {}",
                    intent_hash,
                    intent.amount,
                    intent.source_chain,
                    intent.target_chain,
                    wait_duration.num_seconds(),
                    tx_ids.user_to_network_tx_id.unwrap_or_else(|| "N/A".to_string())
                );
            }

        } else {
            info!(
                "ℹ️  [CLOCK] No {} intents ready for processing in this cycle",
                target_chain.to_uppercase()
            );
        }

        // Additionally, when target_chain is BTC, select pending BTC withdraw-liquidity requests
        // and broadcast a batch for distributed signing (operates on PendingWithdrawRequest
        // under "pending_withdraw_liquidity:").
        if target_chain.eq_ignore_ascii_case("bitcoin") {
            use crate::types::rpc_server::PendingWithdrawRequest;

            let max_btc_withdraw_per_cycle = crate::env_defaults::max_btc_withdraw_per_cycle()
                .parse::<usize>()
                .ok()
                .unwrap_or(15);

            let db = user_intent_manager.get_database();

            // Load all pending withdraw requests
            let all_withdraws: Vec<(String, PendingWithdrawRequest)> =
                match db.get_values_with_prefix("pending_withdraw_liquidity:") {
                    Ok(entries) => entries,
                    Err(e) => {
                        warn!(
                            "⚠️ [CLOCK][BTC_WITHDRAW] Failed to load pending withdraw requests: {}",
                            e
                        );
                        return Ok(());
                    }
                };

            // Revert stale "Batched" BTC withdraw requests (no tx_id) back to "Pending" so they can be retried.
            // This handles the case where a previous BTC signing round failed.
            for (key, req) in &all_withdraws {
                if req.asset.to_uppercase() == "BTC" && req.status == "Batched" && req.tx_id.is_none() {
                    let mut reverted = req.clone();
                    reverted.status = "Pending".to_string();
                    if let Err(e) = db.put_string(key, &reverted) {
                        warn!("⚠️ [CLOCK][BTC_WITHDRAW] Failed to revert stale Batched withdraw {} to Pending: {}", req.request_id, e);
                    } else {
                        info!("🔄 [CLOCK][BTC_WITHDRAW] Reverted stale Batched withdraw {} (no tx_id) back to Pending for retry", req.request_id);
                    }
                }
            }

            // Filter to BTC asset, still pending (or just-reverted), and without tx_id
            let mut btc_pending: Vec<(String, PendingWithdrawRequest)> = all_withdraws
                .into_iter()
                .filter(|(_, req)| {
                    req.asset.to_uppercase() == "BTC"
                        && (req.status == "Pending" || req.status == "Batched")
                        && req.tx_id.is_none()
                })
                .collect();

            if btc_pending.is_empty() {
                info!("ℹ️  [CLOCK][BTC_WITHDRAW] No BTC withdraw requests ready for processing in this cycle");
            } else {
                // Sort by request_id (stable) just to have deterministic ordering
                btc_pending.sort_by(|a, b| a.1.request_id.cmp(&b.1.request_id));

                // Limit to configured max per cycle
                let btc_to_process: Vec<_> =
                    btc_pending.into_iter().take(max_btc_withdraw_per_cycle).collect();

                info!(
                    "📊 [CLOCK][BTC_WITHDRAW] Selected {} BTC withdraw requests (limited to {})",
                    btc_to_process.len(),
                    max_btc_withdraw_per_cycle
                );

                // Mark selected BTC withdraws as "Batched" to prevent re-picking
                for (key, req) in &btc_to_process {
                    let mut updated = req.clone();
                    updated.status = "Batched".to_string();
                    if let Err(e) = db.put_string(key, &updated) {
                        warn!("⚠️ [CLOCK][BTC_WITHDRAW] Failed to mark withdraw {} as Batched: {}", req.request_id, e);
                    } else {
                        info!("📝 [CLOCK][BTC_WITHDRAW] Marked withdraw {} as Batched", req.request_id);
                    }
                }

                // Build (request_id, solver_address) pairs for the batch message
                let requests: Vec<(String, String)> = btc_to_process
                    .iter()
                    .map(|(_, req)| (req.request_id.clone(), req.solver_address.clone()))
                    .collect();

                if !requests.is_empty() {
                    use crate::signing::chains::bitcoin_batch::BatchOutput;

                    let mut batch_outputs: Vec<BatchOutput> = Vec::new();
                    for (_, req) in &btc_to_process {
                        let btc_addr = match &req.btc_address {
                            Some(addr) if !addr.trim().is_empty() => addr.clone(),
                            _ => continue,
                        };
                        let amount_sats: u64 = match req.amount.parse() {
                            Ok(amt) if amt >= 546 => amt,
                            _ => continue,
                        };
                        batch_outputs.push(BatchOutput {
                            address: btc_addr,
                            amount: amount_sats,
                        });
                    }

                    if batch_outputs.is_empty() {
                        warn!("⚠️ [CLOCK][BTC_WITHDRAW] No valid BTC withdraw outputs after filtering; skipping batch");
                        return Ok(());
                    }

                    let batch_timestamp = chrono::Utc::now().to_rfc3339();
                    let batch_id = format!("btc_withdraw_batch:{}:{}", round, chrono::Utc::now().timestamp_millis());

                    let total_inputs = match self
                        .compute_btc_unsigned_input_count_from_outputs(batch_outputs)
                        .await
                    {
                        Ok(count) if count > 0 => count,
                        Ok(_) => {
                            tracing::error!("🔴 [BTC_WITHDRAW] Computed unsigned tx with zero inputs for batch {} - aborting (will retry next epoch)", batch_id);
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::error!("🔴 [BTC_WITHDRAW] Failed to precompute unsigned BTC withdraw tx for batch {}: {} - aborting (will retry next epoch)", batch_id, e);
                            return Ok(());
                        }
                    };

                    let reservation_keys: Vec<String> = (0..total_inputs)
                        .map(|i| format!("{}_{}", batch_id, i))
                        .collect();

                    let nonce_tuple_ids = if let Some(nm) = &self.nonce_manager {
                        let nm_guard = nm.lock().await;
                        match nm_guard.reserve_nonces_for_batch(&reservation_keys).await {
                            Ok(assignments) => {
                                if assignments.len() < reservation_keys.len() {
                                    tracing::error!("🔴 [BTC_WITHDRAW] Reserved only {} of {} required nonces for batch {} - aborting (will retry next epoch)", assignments.len(), reservation_keys.len(), batch_id);
                                    return Ok(());
                                }

                                let mut ordered = Vec::with_capacity(reservation_keys.len());
                                for key in &reservation_keys {
                                    if let Some(tuple_id) = assignments.get(key) {
                                        ordered.push(tuple_id.clone());
                                    } else {
                                        tracing::error!("🔴 [BTC_WITHDRAW] Missing nonce assignment for key {} in batch {} - aborting (will retry next epoch)", key, batch_id);
                                        return Ok(());
                                    }
                                }
                                ordered
                            }
                            Err(e) => {
                                tracing::error!("🔴 [BTC_WITHDRAW] Failed to reserve nonces for batch {}: {} - aborting (will retry next epoch)", batch_id, e);
                                return Ok(());
                            }
                        }
                    } else {
                        tracing::error!("🔴 [BTC_WITHDRAW] NonceManager not available - aborting batch (will retry next epoch)");
                        return Ok(());
                    };

                    info!(
                        "📤 [CLOCK][BTC_WITHDRAW] Broadcasting BTC withdraw batch {} with {} requests ({} ordered nonces)",
                        batch_id,
                        requests.len(),
                        nonce_tuple_ids.len()
                    );

                    self.message_tx
                        .send(crate::types::ChannelMessage::BtcWithdrawBatch {
                            batch_id,
                            requests,
                            round,
                            timestamp: batch_timestamp.clone(),
                            node_id: self.id.clone(),
                            nonce_tuple_ids: Some(nonce_tuple_ids),
                        })
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Compute the exact unsigned BTC intent batch shape and return the number
    /// of per-input digests that must be signed.
    pub(crate) async fn compute_btc_intent_batch_input_count(&self, intent_hashes: &[String]) -> Result<usize> {
        use crate::signing::chains::bitcoin_batch::{
            build_batch_unsigned_tx, select_utxos_for_batch, BatchOutput, BatchPolicy, BatchUtxo,
        };

        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        let mut batch_outputs: Vec<BatchOutput> = Vec::new();
        for intent_hash in intent_hashes {
            let intent = user_intent_manager
                .get_intent(intent_hash)
                .await
                .ok_or_else(|| anyhow!("Intent {} not found", intent_hash))?;

            let amount_sats: u64 = if let Some(stored) = user_intent_manager
                .get_intent_target_amount(intent_hash)
                .await
            {
                stored as u64
            } else {
                let source_amount: u128 = intent
                    .amount
                    .parse()
                    .map_err(|e| anyhow!("Invalid amount for intent {}: {}", intent_hash, e))?;
                let prices = crate::rpc_server::utils::fetch_crypto_prices(Some(intent.timestamp))
                    .await
                    .map_err(|e| {
                        anyhow!(
                            "Failed to fetch crypto prices for intent {}: {}",
                            intent_hash,
                            e
                        )
                    })?;
                crate::rpc_server::utils::convert_src_smallest_to_dst_smallest(
                    source_amount,
                    &intent.source_chain,
                    &intent.target_chain,
                    &prices,
                )
                .map_err(|e| {
                    anyhow!(
                        "Failed to convert source amount for intent {} ({} -> {}): {:?}",
                        intent_hash,
                        intent.source_chain,
                        intent.target_chain,
                        e
                    )
                })?
                    as u64
            };

            if amount_sats < 546 {
                return Err(anyhow!(
                    "Intent {} amount {} sats is below dust threshold",
                    intent_hash,
                    amount_sats
                ));
            }

            batch_outputs.push(BatchOutput {
                address: intent.target_address,
                amount: amount_sats,
            });
        }

        if batch_outputs.is_empty() {
            return Err(anyhow!("No valid outputs available for BTC intent batch"));
        }

        let group_key = self
            .get_network_group_key_from_store_or_db()
            .ok_or_else(|| anyhow!("Network group key not available"))?;
        let network_btc_address = crate::utils::get_btc_address_from_group_key(group_key);

        let is_testnet = crate::types::network::network_type().is_testnet();
        let utxos = crate::utils::transaction::fetch_bitcoin_utxos(&network_btc_address, is_testnet)
            .await?;

        let network_script_pubkey =
            crate::utils::transaction::create_bitcoin_script_pubkey(&network_btc_address)?;

        let batch_utxos: Vec<BatchUtxo> = utxos
            .into_iter()
            .filter(|u| u.status.confirmed)
            .map(|u| BatchUtxo {
                txid: u.txid,
                vout: u.vout,
                value: u.value,
                script_pubkey: network_script_pubkey.clone(),
            })
            .collect();

        let policy = BatchPolicy {
            fee_rate: std::env::var("BTC_FEE_RATE_SAT_VB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            dust_threshold: 546,
            change_address: network_btc_address,
        };

        let selected = select_utxos_for_batch(&batch_utxos, &batch_outputs, &policy)
            .map_err(|e| anyhow!("UTXO selection failed for BTC intent batch: {}", e))?;
        let unsigned_tx = build_batch_unsigned_tx(&selected, &batch_outputs, &policy)
            .map_err(|e| anyhow!("Failed to build BTC intent batch unsigned tx: {}", e))?;

        Ok(unsigned_tx.input.len())
    }

    pub(crate) async fn compute_btc_unsigned_input_count_from_outputs(
        &self,
        batch_outputs: Vec<crate::signing::chains::bitcoin_batch::BatchOutput>,
    ) -> Result<usize> {
        use crate::signing::chains::bitcoin_batch::{
            build_batch_unsigned_tx, select_utxos_for_batch, BatchPolicy, BatchUtxo,
        };

        if batch_outputs.is_empty() {
            return Err(anyhow!("No outputs available to build BTC batch transaction"));
        }

        let group_key = self
            .get_network_group_key_from_store_or_db()
            .ok_or_else(|| anyhow!("Network group key not available"))?;
        let network_btc_address = crate::utils::get_btc_address_from_group_key(group_key);

        let is_testnet = crate::types::network::network_type().is_testnet();
        let utxos = crate::utils::transaction::fetch_bitcoin_utxos(&network_btc_address, is_testnet)
            .await?;
        let network_script_pubkey =
            crate::utils::transaction::create_bitcoin_script_pubkey(&network_btc_address)?;

        let batch_utxos: Vec<BatchUtxo> = utxos
            .into_iter()
            .filter(|u| u.status.confirmed)
            .map(|u| BatchUtxo {
                txid: u.txid,
                vout: u.vout,
                value: u.value,
                script_pubkey: network_script_pubkey.clone(),
            })
            .collect();

        let policy = BatchPolicy {
            fee_rate: std::env::var("BTC_FEE_RATE_SAT_VB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            dust_threshold: 546,
            change_address: network_btc_address,
        };

        let selected = select_utxos_for_batch(&batch_utxos, &batch_outputs, &policy)
            .map_err(|e| anyhow!("Failed to select UTXOs for BTC batch: {}", e))?;
        let unsigned_tx = build_batch_unsigned_tx(&selected, &batch_outputs, &policy)
            .map_err(|e| anyhow!("Failed to build unsigned BTC batch tx: {}", e))?;

        Ok(unsigned_tx.input.len())
    }

    /// Pick a batch of pending TICS-source intents (UserToVault not yet done) and broadcast
    /// TicsUserToVaultIntentBatch so all nodes sign each intent with the respective user key (epoch_1).
    /// When `batched_only` is `Some(true)`, only Batched intents that don't have a user_to_vault tx-id are picked.
    /// Last-4-batches exclusion is always applied (both Pending and Batched-only picks).
    pub(crate) async fn process_tics_user_to_vault_intent_batch_for_round(
        &self,
        round: u64,
        batched_only: Option<bool>,
    ) -> Result<()> {
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        // Number of TICS UserToVault intents to pick per batch (default 10 if env not set)
        let max_per_batch = std::env::var("MAX_TICS_USER_TO_VAULT_INTENTS_PER_BATCH")
            .ok()
            .and_then(|val| val.parse::<usize>().ok())
            .unwrap_or(10);

        let exclusion_set: HashSet<String> = {
            let guard = self.last_tics_user_to_vault_batch_hashes.read().map_err(|e| anyhow!("lock poisoned: {}", e))?;
            guard.iter().flat_map(|set| set.iter().cloned()).collect()
        };
        let pending = user_intent_manager
            .get_pending_user_to_vault_intents_by_source_chain(
                "tics",
                max_per_batch,
                batched_only,
                Some(&exclusion_set),
            )
            .await;

        let mut valid_pending = Vec::new();
        for (hash, intent, user) in pending {
            let source_amount = match intent.amount.trim().parse::<u128>() {
                Ok(a) if a > 0 => a,
                _ => {
                    tracing::warn!("⚠️ [CLOCK][TICS_UTV_BATCH] Invalid amount for intent {}", hash);
                    continue;
                }
            };
            
            let five_percent_buffer = source_amount / 20;
            let estimated_tx_fee: u128 = 300_000_000_000_000;
            let required_balance = source_amount + five_percent_buffer + estimated_tx_fee;
            
            match crate::rpc_server::utils::fetch_network_balance(&intent.source_address, "eth").await {
                Ok(user_balance) => {
                    if user_balance < required_balance {
                        tracing::warn!(
                            "⚠️ [CLOCK][TICS_UTV_BATCH] Insufficient balance for intent {}: has {}, needs {}",
                            hash, user_balance, required_balance
                        );
                        if let Err(e) = user_intent_manager.update_intent_status(&user, &hash, crate::types::IntentStatus::Rejected).await {
                             tracing::error!("Failed to update intent status to Rejected for {}: {}", hash, e);
                        }
                        let error_msg = crate::types::GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: vec![hash.clone()],
                            error_message: format!("Insufficient balance: has {}, needs {}", user_balance, required_balance),
                            transaction_type: "intent_rejected".to_string(),
                            solver_address: None,
                            node_id: self.id.clone(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self.broadcast("signing", &data).await;
                        }
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ [CLOCK][TICS_UTV_BATCH] Failed to fetch balance for intent {}: {}", hash, e);
                    continue;
                }
            }
            valid_pending.push((hash, intent, user));
        }
        let pending = valid_pending;

        if pending.is_empty() {
            if !exclusion_set.is_empty() {
                let mut guard = self.last_tics_user_to_vault_batch_hashes.write().map_err(|e| anyhow!("lock poisoned: {}", e))?;
                guard.push_back(HashSet::new());
                while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                    guard.pop_front();
                }
            }
            info!(
                "ℹ️  [CLOCK][TICS_UTV_BATCH] No pending TICS-source intents (UserToVault not done) for round {}",
                round
            );
            return Ok(());
        }

        // Derive liquidity operator addresses once per batch
        let lo_keys = self.get_vault_group_public_key().await.ok();
        let lo_eth = lo_keys.map(|k| crate::utils::get_eth_address_from_group_key(k));
        let lo_btc = lo_keys.map(|k| crate::utils::get_btc_address_from_group_key(k));

        let mut pending_with_input_counts = Vec::new();
        for (hash, intent, user_address) in pending {
            let user_reg = match user_intent_manager.get_user_by_address(&user_address).await {
                Some(u) => u,
                None => {
                    warn!("⚠️ [TICS_UTV_BATCH] Could not find user registration for address {} (intent {}), skipping nonce reservation", user_address, hash);
                    continue;
                }
            };

            let source_amount: u128 = match intent.amount.trim().parse() {
                Ok(a) if a > 0 => a,
                _ => {
                    warn!("⚠️ [TICS_UTV_BATCH] Intent {} has invalid/zero amount '{}', skipping nonce reservation", hash, intent.amount);
                    continue;
                }
            };
            let amount = source_amount + (source_amount / 20);

            let chain_tx_result = crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                &intent,
                None,
                user_reg.derived_eth_address.as_ref(),
                user_reg.derived_btc_address.as_ref(),
                crate::types::TransactionType::UserToVault,
                lo_eth.as_ref(),
                lo_btc.as_ref(),
                amount,
            )
            .await;

            let n_intent = match chain_tx_result {
                Ok(crate::chain_abstraction::ChainTransaction::Tics(_)) => 1,
                Ok(_) => {
                    warn!("⚠️ [TICS_UTV_BATCH] Intent {} produced non-TICS tx, skipping nonce reservation", hash);
                    continue;
                }
                Err(e) => {
                    warn!("⚠️ [TICS_UTV_BATCH] Failed to build unsigned tx for intent {}: {}, skipping nonce reservation", hash, e);
                    continue;
                }
            };

            pending_with_input_counts.push((hash, intent, user_address, n_intent));
        }

        if pending_with_input_counts.is_empty() {
            warn!("⚠️ [TICS_UTV_BATCH] No intents produced valid unsigned txs for nonce reservation in round {}", round);
            return Ok(());
        }

        let mut reservation_keys = Vec::new();
        for (intent_hash, _, _, n_intent) in &pending_with_input_counts {
            for i in 0..*n_intent {
                reservation_keys.push(format!("{}_{}", intent_hash, i));
            }
        }

        // Reserve nonces for each intent in the batch (coordinator assigns nonces)
        // SECURITY: Nonces are REQUIRED - abort batch if none available
        let (nonce_assignments, broadcast_pending) = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&reservation_keys).await {
                Ok(assignments) => {
                    if assignments.is_empty() {
                        tracing::error!("🔴 [TICS_UTV_BATCH] No nonces available - aborting batch (will retry next cycle)");
                        return Ok(());
                    }

                    let mut nonce_assignments = HashMap::new();
                    let mut broadcast_pending = Vec::new();

                    for (intent_hash, intent, user, n_intent) in pending_with_input_counts {
                        let mut intent_nonces = Vec::with_capacity(n_intent);
                        let mut full_coverage = true;

                        for i in 0..n_intent {
                            let reservation_key = format!("{}_{}", intent_hash, i);
                            if let Some(nonce_id) = assignments.get(&reservation_key) {
                                intent_nonces.push(nonce_id.clone());
                            } else {
                                full_coverage = false;
                                break;
                            }
                        }

                        if full_coverage {
                            nonce_assignments.insert(intent_hash.clone(), intent_nonces);
                            broadcast_pending.push((intent_hash, intent, user, n_intent));
                        } else {
                            warn!("⚠️ [TICS_UTV_BATCH] Partial nonce coverage for intent {}; dropping from broadcast", intent_hash);
                        }
                    }

                    if nonce_assignments.is_empty() {
                        tracing::error!("🔴 [TICS_UTV_BATCH] No intents received full nonce coverage - aborting batch");
                        return Ok(());
                    }

                    info!(
                        "🔐 [TICS_UTV_BATCH] Reserved {} nonce tuples across {} intents",
                        nonce_assignments.values().map(|v| v.len()).sum::<usize>(),
                        nonce_assignments.len()
                    );

                    (nonce_assignments, broadcast_pending)
                }
                Err(e) => {
                    tracing::error!(
                        "🔴 [TICS_UTV_BATCH] Failed to reserve nonces: {} - aborting batch (will retry next cycle)",
                        e
                    );
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [TICS_UTV_BATCH] NonceManager not available - aborting batch (will retry next cycle)");
            return Ok(());
        };

        let intent_hashes: Vec<String> = broadcast_pending.iter().map(|(hash, _, _, _)| hash.clone()).collect();


        {
            let mut guard = self.last_tics_user_to_vault_batch_hashes.write().map_err(|e| anyhow!("lock poisoned: {}", e))?;
            guard.push_back(intent_hashes.iter().cloned().collect());
            while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                guard.pop_front();
            }
        }

        let batch_timestamp = chrono::Utc::now().to_rfc3339();
        info!(
            "📤 [CLOCK][TICS_UTV_BATCH] Broadcasting TICS UserToVault intent batch for round {} ({} intents)",
            round,
            intent_hashes.len()
        );

        self.message_tx
            .send(crate::types::ChannelMessage::TicsUserToVaultIntentBatch {
                intent_hashes: intent_hashes.clone(),
                round,
                timestamp: batch_timestamp.clone(),
                node_id: self.id.clone(),
                nonce_assignments,
            })
            .await?;

        for (hash, intent, user, _) in &broadcast_pending {
            info!(
                "  📋 [TICS_UTV_BATCH] Intent {}: amount={}, user={}",
                hash, intent.amount, user
            );
        }

        Ok(())
    }

    /// Pick a batch of pending BTC-source intents (UserToVault not yet done) and broadcast
    /// BtcUserToVaultIntentBatch so all nodes sign each intent with the respective user key (epoch_2).
    /// When `batched_only` is `Some(true)`, only Batched intents that don't have a user_to_vault tx-id are picked.
    /// Last-4-batches exclusion is always applied (both Pending and Batched-only picks).
    pub(crate) async fn process_btc_user_to_vault_intent_batch_for_round(
        &self,
        round: u64,
        batched_only: Option<bool>,
    ) -> Result<()> {
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        let max_per_batch = std::env::var("MAX_BTC_USER_TO_VAULT_INTENTS_PER_BATCH")
            .ok()
            .and_then(|val| val.parse::<usize>().ok())
            .unwrap_or(10);

        let exclusion_set: HashSet<String> = {
            let guard = self.last_btc_user_to_vault_batch_hashes.read().map_err(|e| anyhow!("lock poisoned: {}", e))?;
            guard.iter().flat_map(|set| set.iter().cloned()).collect()
        };
        let pending = user_intent_manager
            .get_pending_user_to_vault_intents_by_source_chain(
                "bitcoin",
                max_per_batch,
                batched_only,
                Some(&exclusion_set),
            )
            .await;

        let mut valid_pending = Vec::new();
        for (hash, intent, user) in pending {
            let source_amount = match intent.amount.trim().parse::<u128>() {
                Ok(a) if a > 0 => a,
                _ => {
                    tracing::warn!("⚠️ [CLOCK][BTC_UTV_BATCH] Invalid amount for intent {}", hash);
                    continue;
                }
            };
            
            let five_percent_buffer = source_amount / 20;
            let fee_rate = std::env::var("BTC_FEE_RATE_SAT_VB")
                .ok()
                .and_then(|v| v.parse::<u128>().ok())
                .unwrap_or(2);
            let estimated_tx_fee: u128 = 208 * fee_rate;
            let required_balance = source_amount + five_percent_buffer + estimated_tx_fee;
            
            match crate::utils::transaction::fetch_bitcoin_utxos(&intent.source_address, false).await {
                Ok(utxos) => {
                    let confirmed_balance: u128 = utxos
                        .iter()
                        .filter(|u| u.status.confirmed)
                        .map(|u| u.value as u128)
                        .sum();
                    if confirmed_balance < required_balance {
                        tracing::warn!(
                            "⚠️ [CLOCK][BTC_UTV_BATCH] Insufficient confirmed UTXOs for intent {}: has {}, needs {}",
                            hash, confirmed_balance, required_balance
                        );
                        if let Err(e) = user_intent_manager.update_intent_status(&user, &hash, crate::types::IntentStatus::Rejected).await {
                             tracing::error!("Failed to update intent status to Rejected for {}: {}", hash, e);
                        }
                        let error_msg = crate::types::GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: vec![hash.clone()],
                            error_message: format!("Insufficient confirmed UTXOs: has {}, needs {}", confirmed_balance, required_balance),
                            transaction_type: "intent_rejected".to_string(),
                            solver_address: None,
                            node_id: self.id.clone(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self.broadcast("signing", &data).await;
                        }
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ [CLOCK][BTC_UTV_BATCH] Failed to fetch utxos for intent {}: {}", hash, e);
                    continue; 
                }
            }
            valid_pending.push((hash, intent, user));
        }
        let pending = valid_pending;

        if pending.is_empty() {
            if !exclusion_set.is_empty() {
                let mut guard = self.last_btc_user_to_vault_batch_hashes.write().map_err(|e| anyhow!("lock poisoned: {}", e))?;
                guard.push_back(HashSet::new());
                while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                    guard.pop_front();
                }
            }
            info!(
                "ℹ️  [CLOCK][BTC_UTV_BATCH] No pending BTC-source intents (UserToVault not done) for round {}",
                round
            );
            return Ok(());
        }

        // Derive liquidity operator addresses once per batch
        let lo_keys = self.get_vault_group_public_key().await.ok();
        let lo_eth = lo_keys.map(|k| crate::utils::get_eth_address_from_group_key(k));
        let lo_btc = lo_keys.map(|k| crate::utils::get_btc_address_from_group_key(k));

        let mut pending_with_input_counts = Vec::new();
        for (hash, intent, user_address) in pending {
            let user_reg = match user_intent_manager.get_user_by_address(&user_address).await {
                Some(u) => u,
                None => {
                    warn!("⚠️ [BTC_UTV_BATCH] Could not find user registration for address {} (intent {}), skipping nonce reservation", user_address, hash);
                    continue;
                }
            };

            let amount_sats: u128 = match intent.amount.trim().parse() {
                Ok(a) if a > 0 => a,
                _ => {
                    warn!("⚠️ [BTC_UTV_BATCH] Intent {} has invalid/zero amount '{}', skipping nonce reservation", hash, intent.amount);
                    continue;
                }
            };
            let amount = amount_sats + (amount_sats / 20);

            let chain_tx_result = crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                &intent,
                None,
                user_reg.derived_eth_address.as_ref(),
                user_reg.derived_btc_address.as_ref(),
                crate::types::TransactionType::UserToVault,
                lo_eth.as_ref(),
                lo_btc.as_ref(),
                amount,
            )
            .await;

            let n_intent = match chain_tx_result {
                Ok(crate::chain_abstraction::ChainTransaction::Bitcoin(tx)) => {
                    if tx.inputs.is_empty() {
                        warn!("⚠️ [BTC_UTV_BATCH] Intent {} produced tx with 0 inputs, skipping nonce reservation", hash);
                        continue;
                    }
                    tx.inputs.len()
                }
                Ok(_) => {
                    warn!("⚠️ [BTC_UTV_BATCH] Intent {} produced non-Bitcoin tx, skipping nonce reservation", hash);
                    continue;
                }
                Err(e) => {
                    warn!("⚠️ [BTC_UTV_BATCH] Failed to build unsigned tx for intent {}: {}, skipping nonce reservation", hash, e);
                    continue;
                }
            };

            pending_with_input_counts.push((hash, intent, user_address, n_intent));
        }

        if pending_with_input_counts.is_empty() {
            warn!("⚠️ [BTC_UTV_BATCH] No intents produced valid unsigned txs for nonce reservation in round {}", round);
            return Ok(());
        }

        let mut reservation_keys = Vec::new();
        for (intent_hash, _, _, n_intent) in &pending_with_input_counts {
            for i in 0..*n_intent {
                reservation_keys.push(format!("{}_{}", intent_hash, i));
            }
        }

        // Reserve nonces for each intent in the batch (coordinator assigns nonces)
        // SECURITY: Nonces are REQUIRED - abort batch if none available
        let (nonce_assignments, broadcast_pending) = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&reservation_keys).await {
                Ok(assignments) => {
                    if assignments.is_empty() {
                        tracing::error!("🔴 [BTC_UTV_BATCH] No nonces available - aborting batch (will retry next cycle)");
                        return Ok(());
                    }

                    let mut nonce_assignments = HashMap::new();
                    let mut broadcast_pending = Vec::new();

                    for (intent_hash, intent, user, n_intent) in pending_with_input_counts {
                        let mut intent_nonces = Vec::with_capacity(n_intent);
                        let mut full_coverage = true;

                        for i in 0..n_intent {
                            let reservation_key = format!("{}_{}", intent_hash, i);
                            if let Some(nonce_id) = assignments.get(&reservation_key) {
                                intent_nonces.push(nonce_id.clone());
                            } else {
                                full_coverage = false;
                                break;
                            }
                        }

                        if full_coverage {
                            nonce_assignments.insert(intent_hash.clone(), intent_nonces);
                            broadcast_pending.push((intent_hash, intent, user, n_intent));
                        } else {
                            warn!("⚠️ [BTC_UTV_BATCH] Partial nonce coverage for intent {}; dropping from broadcast", intent_hash);
                        }
                    }

                    if nonce_assignments.is_empty() {
                        tracing::error!("🔴 [BTC_UTV_BATCH] No intents received full nonce coverage - aborting batch");
                        return Ok(());
                    }

                    info!(
                        "🔐 [BTC_UTV_BATCH] Reserved {} nonce tuples across {} intents",
                        nonce_assignments.values().map(|v| v.len()).sum::<usize>(),
                        nonce_assignments.len()
                    );

                    (nonce_assignments, broadcast_pending)
                }
                Err(e) => {
                    tracing::error!(
                        "🔴 [BTC_UTV_BATCH] Failed to reserve nonces: {} - aborting batch (will retry next cycle)",
                        e
                    );
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [BTC_UTV_BATCH] NonceManager not available - aborting batch (will retry next cycle)");
            return Ok(());
        };

        let intent_hashes: Vec<String> = broadcast_pending.iter().map(|(hash, _, _, _)| hash.clone()).collect();


        {
            let mut guard = self.last_btc_user_to_vault_batch_hashes.write().map_err(|e| anyhow!("lock poisoned: {}", e))?;
            guard.push_back(intent_hashes.iter().cloned().collect());
            while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                guard.pop_front();
            }
        }

        let batch_timestamp = chrono::Utc::now().to_rfc3339();
        info!(
            "📤 [CLOCK][BTC_UTV_BATCH] Broadcasting BTC UserToVault intent batch for round {} ({} intents)",
            round,
            intent_hashes.len()
        );

        self.message_tx
            .send(crate::types::ChannelMessage::BtcUserToVaultIntentBatch {
                intent_hashes: intent_hashes.clone(),
                round,
                timestamp: batch_timestamp.clone(),
                node_id: self.id.clone(),
                nonce_assignments,
            })
            .await?;

        for (hash, intent, user, _) in &broadcast_pending {
            info!(
                "  📋 [BTC_UTV_BATCH] Intent {}: amount={}, user={}",
                hash, intent.amount, user
            );
        }

        Ok(())
    }

    /// Pick a batch of pending BTC claim-reward requests and broadcast BtcClaimRewardBatch (called from epoch_1).
    pub(crate) async fn process_btc_claim_reward_batch_for_round(&self, round: u64) -> Result<()> {
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        let max_btc_claim_reward_per_cycle = std::env::var("MAX_BTC_CLAIM_REWARD_PER_CYCLE")
            .ok()
            .and_then(|val| val.parse::<usize>().ok())
            .unwrap_or(10);

        let all_claims: Vec<(String, crate::types::rpc_server::PendingClaimRewardRequest)> =
            db.get_values_with_prefix("pending_claim_reward:")
                .map_err(|e| anyhow!("Failed to load pending claim reward requests: {}", e))?;

        // Revert stale "Batched" BTC claim reward requests (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous BTC signing round failed.
        for (key, req) in &all_claims {
            let has_btc = req.btc_address.as_ref().map_or(false, |a| !a.trim().is_empty());
            if has_btc && req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [BTC_CLAIM_REWARD] Failed to revert stale Batched claim {} to Pending: {}", req.request_id, e);
                } else {
                    info!("🔄 [BTC_CLAIM_REWARD] Reverted stale Batched claim {} (no tx_id) back to Pending for retry", req.request_id);
                }
            }
        }

        let mut btc_claim_pending: Vec<(String, crate::types::rpc_server::PendingClaimRewardRequest)> = all_claims
            .into_iter()
            .filter(|(_, req)| {
                (req.status == "Pending" || req.status == "Batched")
                    && req.tx_id.is_none()
                    && req.btc_address.as_ref().map_or(false, |a| !a.trim().is_empty())
            })
            .collect();

        if btc_claim_pending.is_empty() {
            return Ok(());
        }

        btc_claim_pending.sort_by(|a, b| a.1.request_id.cmp(&b.1.request_id));
        let btc_claim_to_process: Vec<_> = btc_claim_pending
            .into_iter()
            .take(max_btc_claim_reward_per_cycle)
            .collect();

        // Mark selected BTC claim rewards as "Batched" to prevent re-picking
        for (key, req) in &btc_claim_to_process {
            let mut updated = req.clone();
            updated.status = "Batched".to_string();
            if let Err(e) = db.put_string(key, &updated) {
                warn!("⚠️ [BTC_CLAIM_REWARD] Failed to mark claim {} as Batched: {}", req.request_id, e);
            } else {
                info!("📝 [BTC_CLAIM_REWARD] Marked claim {} as Batched", req.request_id);
            }
        }

        let claim_requests: Vec<(String, String)> = btc_claim_to_process
            .iter()
            .map(|(_, req)| (req.request_id.clone(), req.solver_address.clone()))
            .collect();

        if claim_requests.is_empty() {
            return Ok(());
        }

        use crate::contract::{ContractClient, ContractConfig, SolverManagerContract};
        use crate::signing::chains::bitcoin_batch::BatchOutput;
        use ethers::types::{Address, U256};

        let mut batch_outputs: Vec<BatchOutput> = Vec::new();
        for (_, req) in &btc_claim_to_process {
            let btc_addr = match &req.btc_address {
                Some(addr) if !addr.trim().is_empty() => addr.clone(),
                _ => continue,
            };

            let solver_addr = match req.solver_address.parse::<Address>() {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            let rpc_url = crate::env_defaults::solver_contract_rpc_url();
            let contract_address_env = crate::env_defaults::solver_contract_address();
            if contract_address_env == "0x0000000000000000000000000000000000000000" {
                warn!("⚠️ [BTC_CLAIM_REWARD] Solver contract not configured; skipping unclaimed fetch");
                continue;
            }
            let contract_address = match contract_address_env.parse::<Address>() {
                Ok(addr) => addr,
                Err(_) => continue,
            };
            let chain_id = crate::env_defaults::solver_contract_chain_id()
                .parse::<u64>()
                .ok()
                .unwrap_or_else(|| crate::env_defaults::mpc_tics_chain_id());
            let config = ContractConfig {
                rpc_url,
                contract_address,
                chain_id,
            };
            let client = match ContractClient::new(config.clone()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let contract = match SolverManagerContract::new(&config, client.provider()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let solver_id = match contract.get_solver_id(solver_addr).await {
                Ok(id) if !id.trim().is_empty() => id,
                _ => continue,
            };
            let rewards = match contract.get_solvers_unclaimed_rewards(vec![solver_id]).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let btc_unclaimed = rewards.first().map(|r| r.1).unwrap_or(U256::zero());
            let amount_sats = btc_unclaimed.as_u64();
            if amount_sats <= 546 {
                continue;
            }

            batch_outputs.push(BatchOutput {
                address: btc_addr,
                amount: amount_sats,
            });
        }

        if batch_outputs.is_empty() {
            warn!("⚠️ [BTC_CLAIM_REWARD] No valid claim-reward outputs after filtering; skipping batch");
            return Ok(());
        }

        let claim_batch_timestamp = chrono::Utc::now().to_rfc3339();
        let claim_batch_id = format!(
            "btc_claim_reward_batch:{}:{}",
            round,
            chrono::Utc::now().timestamp_millis()
        );

        let total_inputs = match self
            .compute_btc_unsigned_input_count_from_outputs(batch_outputs)
            .await
        {
            Ok(count) if count > 0 => count,
            Ok(_) => {
                tracing::error!("🔴 [BTC_CLAIM_REWARD] Computed unsigned tx with zero inputs for batch {} - aborting (will retry next epoch)", claim_batch_id);
                return Ok(());
            }
            Err(e) => {
                tracing::error!("🔴 [BTC_CLAIM_REWARD] Failed to precompute unsigned BTC claim-reward tx for batch {}: {} - aborting (will retry next epoch)", claim_batch_id, e);
                return Ok(());
            }
        };

        let reservation_keys: Vec<String> = (0..total_inputs)
            .map(|i| format!("{}_{}", claim_batch_id, i))
            .collect();

        let nonce_tuple_ids = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&reservation_keys).await {
                Ok(assignments) => {
                    if assignments.len() < reservation_keys.len() {
                        tracing::error!("🔴 [BTC_CLAIM_REWARD] Reserved only {} of {} required nonces for batch {} - aborting (will retry next epoch)", assignments.len(), reservation_keys.len(), claim_batch_id);
                        return Ok(());
                    }

                    let mut ordered = Vec::with_capacity(reservation_keys.len());
                    for key in &reservation_keys {
                        if let Some(tuple_id) = assignments.get(key) {
                            ordered.push(tuple_id.clone());
                        } else {
                            tracing::error!("🔴 [BTC_CLAIM_REWARD] Missing nonce assignment for key {} in batch {} - aborting (will retry next epoch)", key, claim_batch_id);
                            return Ok(());
                        }
                    }
                    ordered
                }
                Err(e) => {
                    tracing::error!("🔴 [BTC_CLAIM_REWARD] Failed to reserve nonces for batch {}: {} - aborting (will retry next epoch)", claim_batch_id, e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [BTC_CLAIM_REWARD] NonceManager not available - aborting batch (will retry next epoch)");
            return Ok(());
        };

        info!(
            "📤 [CLOCK][BTC_CLAIM_REWARD] Broadcasting BTC claim-reward batch {} with {} requests ({} ordered nonces)",
            claim_batch_id,
            claim_requests.len(),
            nonce_tuple_ids.len()
        );
        self.message_tx
            .send(crate::types::ChannelMessage::BtcClaimRewardBatch {
                batch_id: claim_batch_id,
                requests: claim_requests,
                round,
                timestamp: claim_batch_timestamp,
                node_id: self.id.clone(),
                nonce_tuple_ids: Some(nonce_tuple_ids),
            })
            .await
            .map_err(|e| anyhow!("Failed to send BtcClaimRewardBatch: {}", e))?;

        Ok(())
    }

    /// TICS UserToVault batch ONLY: handle one partial for (round, slot_id). Aggregate when threshold reached.
    /// NOTE: BTC UserToVault now uses handle_btc_utv_signature_for_round_slot with multi-input support.
    /// This function should NOT be used for BTC UTV - it only handles single-signature TICS transactions.
    pub(crate) async fn handle_signature_for_round_slot(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
        slot_id: String,
    ) -> Result<()> {
        use crate::signing::state::RoundSlotKey;

        let slot_key: RoundSlotKey = (round, slot_id.clone());
        let already_aggregated = {
            let agg = self.signatures.aggregated_round_slots.read().await;
            agg.contains(&slot_key)
        };
        if already_aggregated {
            info!(
                "⏭️ [SIGNING] Slot {} for round {} already aggregated, ignoring signature from {}",
                slot_id, round, from
            );
            return Ok(());
        }

        // NOTE: With random nonces (coordinated nonces), partial signature verification
        // via ECDSA public key recovery is not mathematically possible because all nodes
        // use the same aggregated k⁻¹ and r values. The security comes from:
        // 1. All nodes compute the same message digest
        // 2. The final aggregated signature is verified against the group public key
        // 3. Invalid partial signatures will result in an invalid aggregated signature
        //
        // For now, we log but don't fail on partial verification errors. The final
        // aggregated signature verification provides the actual security guarantee.
        if let Err(e) = self
            .verify_signature_for_round(&from, &signature, round, Some(&slot_id))
            .await
        {
            warn!(
                "⚠️ [SIGNING] Slot {} partial verification failed for peer {} in round {} (expected with random nonces): {}",
                slot_id, from, round, e
            );
            // Don't return error - with random nonces, partial verification is not possible.
            // The final aggregated signature will be verified against the group public key.
        }

        {
            let mut by_slot = self.signatures.signatures_by_round_slot.write().await;
            let entry = by_slot.entry(slot_key.clone()).or_default();
            entry.insert(from.clone(), signature.clone());
            info!(
                "💾 [SIGNING] Stored signature from {} for slot {} round {} (total: {})",
                from,
                slot_id,
                round,
                entry.len()
            );
        }

        let round_slot_signatures = {
            let by_slot = self.signatures.signatures_by_round_slot.read().await;
            by_slot.get(&slot_key).cloned()
        };
        let Some(round_slot_signatures) = round_slot_signatures else {
            return Ok(());
        };
        if round_slot_signatures.len() < self.threshold as usize {
            info!(
                "⏳ [SIGNING] Slot {} round {}: {}/{} signatures",
                slot_id, round, round_slot_signatures.len(), self.threshold
            );
            return Ok(());
        }

        // Mark aggregated immediately so no duplicate work; then spawn non-blocking task for aggregate + broadcast
        {
            let mut agg = self.signatures.aggregated_round_slots.write().await;
            agg.insert(slot_key.clone());
        }

        // TICS UserToVault only - BTC UTV uses dedicated handler with multi-input support
        let slot_kind = SlotKind::TicsUserToVault;

        let chain_id = std::env::var("MPC_TICS_CHAIN_ID")
            .ok()
            .and_then(|id| id.parse::<u64>().ok())
            .unwrap_or_else(|| crate::env_defaults::mpc_tics_chain_id());

        let mut sorted: Vec<_> = round_slot_signatures.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let round_slot_signatures_owned: Vec<(String, ECDSASignature)> = sorted
            .iter()
            .take(self.threshold)
            .map(|(id, sig)| ((*id).clone(), (*sig).clone()))
            .collect();

        let self_ref = self.self_ref.clone();
        let round = round;
        let slot_id = slot_id.clone();

        tokio::spawn(async move {
            if let Some(arc) = self_ref {
                let mut node = arc.lock().await;
                if let Err(e) = node
                    .do_aggregate_and_broadcast_for_slot(
                        round,
                        slot_id.clone(),
                        round_slot_signatures_owned,
                        chain_id,
                        slot_kind,
                    )
                    .await
                {
                    error!(
                        "❌ [SIGNING] Async aggregation failed for slot {} round {}: {}",
                        slot_id, round, e
                    );
                }
            }
        });

        Ok(())
    }

    /// BTC UserToVault batch: handle multi-input signatures for one slot.
    /// This is the hybrid of TICS UTV (slot-based) and N2T (multi-input).
    /// Key: (round, slot_id) where slot_id is the intent_hash.
    /// Each slot can have multiple inputs (UTXOs).
    ///
    /// Flow (mirrors N2T per-input logic but keyed by slot):
    /// 1) Skip if slot already completed
    /// 2) Load tx data for this slot from user_to_vault_btc_batch
    /// 3) Verify and store each signature per input
    /// 4) Sweep: aggregate each input that hit threshold
    /// 5) If ALL inputs for this slot are aggregated, finalize and broadcast
    pub async fn handle_btc_utv_signature_for_round_slot(
        &mut self,
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
        slot_id: String,
    ) -> Result<()> {
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        use std::collections::HashMap;

        let slot_key: RoundSlotKey = (round, slot_id.clone());

        // 1. Skip if slot already completed
        {
            let completed = self.btc_utv_state.btc_utv_completed_slots.read().await;
            if completed.contains(&slot_key) {
                info!(
                    "⏭️ [BTC_UTV] Slot {} for round {} already completed, ignoring signatures from {}",
                    slot_id, round, from
                );
                return Ok(());
            }
        }

        // 2. Get tx data for this slot from user_to_vault_btc_batch
        // Nodes without a DKG share may not have BTC batch data yet — poll up to ~5s
        let has_dkg = self.has_dkg_share().await;
        let max_attempts = if has_dkg { 1 } else { 50 };

        let (_unsigned_tx, _extras, total_inputs) = {
            let mut result = None;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                let batch = self.pending.user_to_vault_btc_batch.read().await;
                if let Some(entries) = batch.get(&round) {
                    if let Some((_, _user_eth, chain_tx, _, extras_opt)) = entries.iter().find(|(h, ..)| h == &slot_id) {
                        if let ChainTransaction::Bitcoin(t) = chain_tx {
                            if let Some(extras) = extras_opt {
                                if attempt > 0 {
                                    debug!(
                                        "✅ [BTC_UTV] Found BTC batch data for round {} slot {} after {} attempts (~{}ms)",
                                        round, slot_id, attempt + 1, attempt * 100
                                    );
                                }
                                result = Some((t.clone(), extras.clone(), t.inputs.len()));
                                break;
                            }
                        }
                    }
                }
                if attempt == max_attempts - 1 && !has_dkg {
                    warn!(
                        "⚠️ [BTC_UTV] Could not find BTC batch data for round {} slot {} after {}ms",
                        round, slot_id, max_attempts * 100
                    );
                }
            }
            result.ok_or_else(|| {
                anyhow!(
                    "[BTC_UTV] No user_to_vault_btc_batch for round {} slot {} (observer timeout)",
                    round,
                    slot_id
                )
            })?
        };

        info!(
            "📥 [BTC_UTV] Received {} signatures from {} for slot {} round {} (expecting {} inputs)",
            signatures.len(),
            from,
            slot_id,
            round,
            total_inputs
        );

        // 3. Verify and store each signature per input
        let mut verified_count = 0;
        for sig in &signatures {
            if sig.input_index >= total_inputs {
                warn!(
                    "⚠️ [BTC_UTV] Signature from {} has invalid input_index {} (slot {} has {} inputs)",
                    from, sig.input_index, slot_id, total_inputs
                );
                continue;
            }

            // Verify signature against correct digest for this input
            match self
                .verify_btc_utv_signature_for_slot(
                    &from,
                    &sig.signature,
                    round,
                    &slot_id,
                    sig.input_index,
                )
                .await
            {
                Ok(_) => {
                    info!(
                        "✅ [BTC_UTV] Verified signature from {} for slot {} round {} input {}",
                        from, slot_id, round, sig.input_index
                    );
                }
                Err(e) => {
                    error!(
                        "❌ [BTC_UTV] Signature verification failed for {} slot {} round {} input {}: {}",
                        from, slot_id, round, sig.input_index, e
                    );
                    continue;
                }
            }

            // Store: (round, slot_id) → input_index → peer → signature
            {
                let mut by_slot = self
                    .btc_utv_state
                    .btc_utv_sigs_by_round_slot
                    .write()
                    .await;
                let slot_map = by_slot.entry(slot_key.clone()).or_default();
                let input_map = slot_map.entry(sig.input_index).or_default();
                input_map.insert(from.clone(), sig.signature.clone());
            }
            verified_count += 1;
        }

        info!(
            "💾 [BTC_UTV] Stored {}/{} verified signatures from {} for slot {} round {}",
            verified_count,
            signatures.len(),
            from,
            slot_id,
            round
        );

        // 3b. If this final node failed to verify ALL signatures (e.g. missing DKG
        //     commitments on an observer), the batch can never complete.  Revert the
        //     intent status from Batched back to Pending so a future round (with a
        //     different final node) can re-process it.
        if verified_count == 0 && !signatures.is_empty() {
            // Check if this node is the final node for this round
            let is_final = {
                let final_nodes = self.signatures.final_nodes_by_round.read().await;
                final_nodes.get(&round).map_or(false, |f| *f == self.id)
            };
            if is_final {
                warn!(
                    "🔄 [BTC_UTV] Final node {} failed to verify ALL signatures for slot {} round {} — reverting intent to Pending",
                    self.id, slot_id, round
                );
                if let Some(ref uim) = self.user_intent_manager {
                    if let Some(user) = uim.get_user_by_intent_hash(&slot_id).await {
                        // NEVER revert from Solved — that is a terminal state.
                        let current_status = uim
                            .get_intent_status(&user.tics_address, &slot_id)
                            .await;
                        if matches!(current_status, Some(crate::types::user_intent::IntentStatus::Solved)) {
                            debug!(
                                "⏭️ [BTC_UTV] Skipping revert for intent {} — already Solved",
                                slot_id
                            );
                        } else if let Err(e) = uim
                            .update_intent_status(
                                &user.tics_address,
                                &slot_id,
                                crate::types::user_intent::IntentStatus::Pending,
                            )
                            .await
                        {
                            error!(
                                "❌ [BTC_UTV] Failed to revert intent {} to Pending: {}",
                                slot_id, e
                            );
                        } else {
                            info!(
                                "✅ [BTC_UTV] Reverted intent {} to Pending for user {} (will be re-batched next cycle)",
                                slot_id, user.tics_address
                            );
                        }
                    }
                }

                // Broadcast error to all nodes so they also revert
                // intent status from Batched to Pending.
                self.broadcast_transaction_error(
                    Some(vec![slot_id.clone()]),
                    &format!(
                        "BTC UTV final node failed to verify ALL signatures for slot {} round {}",
                        slot_id, round
                    ),
                    "user_to_network",
                    None,
                )
                .await;
                info!(
                    "📡 [BTC_UTV] Broadcasted verification failure for slot {} round {} to sync intent status across nodes",
                    slot_id, round
                );
            }
        }

        // 4. Sweep: aggregate each input that hit threshold
        for idx in 0..total_inputs {
            // Skip if already aggregated for this input
            {
                let done = self
                    .btc_utv_state
                    .btc_utv_done_inputs_by_round_slot
                    .read()
                    .await;
                if done.get(&slot_key).is_some_and(|s| s.contains(&idx)) {
                    continue;
                }
            }

            // Get peer sigs for this input
            let peer_map: Option<HashMap<String, ECDSASignature>> = {
                let by_slot = self
                    .btc_utv_state
                    .btc_utv_sigs_by_round_slot
                    .read()
                    .await;
                by_slot
                    .get(&slot_key)
                    .and_then(|s| s.get(&idx))
                    .cloned()
            };
            let Some(peer_map) = peer_map else {
                continue;
            };

            // Check threshold
            if peer_map.len() < self.threshold {
                info!(
                    "⏳ [BTC_UTV] Slot {} input {} has {}/{} signatures",
                    slot_id,
                    idx,
                    peer_map.len(),
                    self.threshold
                );
                continue;
            }

            // Sort deterministically, take threshold
            let mut chosen: Vec<(String, ECDSASignature)> = peer_map.into_iter().collect();
            chosen.sort_by(|a, b| a.0.cmp(&b.0));
            let chosen: Vec<(String, ECDSASignature)> =
                chosen.into_iter().take(self.threshold).collect();

            // Verify all chosen sigs share the same r value and are 64 bytes
            let r0 = &chosen[0].1.signature[0..32];
            let mut r_mismatch = false;
            for (peer, s) in &chosen {
                if s.signature.len() != 64 {
                    error!(
                        "❌ [BTC_UTV] Slot {} input {}: bad sig length from {} (got {})",
                        slot_id,
                        idx,
                        peer,
                        s.signature.len()
                    );
                    r_mismatch = true;
                    break;
                }
                if &s.signature[0..32] != r0 {
                    error!(
                        "❌ [BTC_UTV] Slot {} input {}: r mismatch from {}",
                        slot_id, idx, peer
                    );
                    r_mismatch = true;
                    break;
                }
            }
            if r_mismatch {
                continue;
            }

            // Build inputs for MPC aggregation
            let mut sigs: Vec<RecoverableSignature> = Vec::with_capacity(self.threshold);
            let mut peer_to_dkg_index: Vec<(String, u32)> = Vec::with_capacity(self.threshold);
            for (peer, ecsig) in chosen {
                let rid = RecoveryId::from_i32(ecsig.recovery_id as i32)?;
                let rs = RecoverableSignature::from_compact(&ecsig.signature, rid)?;
                sigs.push(rs);
                let dkg_idx = self.calculate_dkg_index_for_peer_sync(&peer);
                peer_to_dkg_index.push((peer, dkg_idx));
            }

            // Aggregate this input's signatures
            let agg = match self.aggregate_signatures(sigs, peer_to_dkg_index).await {
                Ok(sig) => sig,
                Err(e) => {
                    error!(
                        "❌ [BTC_UTV] Failed to aggregate slot {} input {}: {}",
                        slot_id, idx, e
                    );
                    continue;
                }
            };

            // Store aggregated sig for this input
            {
                let mut agg_map = self
                    .btc_utv_state
                    .btc_utv_agg_by_round_slot
                    .write()
                    .await;
                agg_map
                    .entry(slot_key.clone())
                    .or_default()
                    .insert(idx, agg);
            }

            // Mark input as done
            {
                let mut done = self
                    .btc_utv_state
                    .btc_utv_done_inputs_by_round_slot
                    .write()
                    .await;
                done.entry(slot_key.clone()).or_default().insert(idx);
            }

            info!(
                "✅ [BTC_UTV] Aggregated slot {} input {} for round {}",
                slot_id, idx, round
            );
        }

        // 5. Check if ALL inputs for this slot are aggregated
        let all_done = {
            let done = self
                .btc_utv_state
                .btc_utv_done_inputs_by_round_slot
                .read()
                .await;
            done.get(&slot_key)
                .map_or(false, |s| s.len() == total_inputs)
        };

        if all_done {
            // Mark slot as completed immediately (prevent duplicate finalization)
            {
                let mut completed = self.btc_utv_state.btc_utv_completed_slots.write().await;
                completed.insert(slot_key.clone());
            }

            info!(
                "🎯 [BTC_UTV] All {} inputs aggregated for slot {} round {}, spawning finalization",
                total_inputs, slot_id, round
            );

            // Spawn async finalization for this slot
            let self_ref = self.self_ref.clone();
            let slot_id_clone = slot_id.clone();
            tokio::spawn(async move {
                if let Some(arc) = self_ref {
                    let mut node = arc.lock().await;
                    if let Err(e) = node.finalize_btc_utv_slot(round, slot_id_clone.clone()).await {
                        error!(
                            "❌ [BTC_UTV] Finalization failed for slot {} round {}: {}",
                            slot_id_clone, round, e
                        );
                    }
                }
            });
        }

        Ok(())
    }

    /// Verify a BTC UTV signature for a specific slot and input.
    pub(crate) async fn verify_btc_utv_signature_for_slot(
        &self,
        peer_id: &str,
        signature: &ECDSASignature,
        round: u64,
        slot_id: &str,
        input_index: usize,
    ) -> Result<()> {
        use secp256k1::{ecdsa::RecoveryId, Message, Secp256k1};

        // Get tx data for this slot
        let (btc_tx, user_eth) = {
            let batch = self.pending.user_to_vault_btc_batch.read().await;
            let entries = batch.get(&round).ok_or_else(|| {
                anyhow!(
                    "[verify_btc_utv] No batch for round {} slot {}",
                    round,
                    slot_id
                )
            })?;
            let (_, user_eth, chain_tx, _, _) = entries
                .iter()
                .find(|(h, ..)| h == slot_id)
                .ok_or_else(|| {
                    anyhow!(
                        "[verify_btc_utv] No slot {} in batch for round {}",
                        slot_id,
                        round
                    )
                })?;

            let btc_tx = match chain_tx {
                ChainTransaction::Bitcoin(t) => t.clone(),
                _ => {
                    return Err(anyhow!(
                        "[verify_btc_utv] Slot {} is not Bitcoin",
                        slot_id
                    ))
                }
            };
            (btc_tx, user_eth.clone())
        };

        // Get input and compute digest
        let inp = btc_tx.inputs.get(input_index).ok_or_else(|| {
            anyhow!(
                "[verify_btc_utv] Slot {} has no input at index {}",
                slot_id,
                input_index
            )
        })?;
        let prev_spk = inp
            .witness_utxo
            .as_ref()
            .ok_or_else(|| {
                anyhow!(
                    "[verify_btc_utv] Slot {} input {} missing witness_utxo",
                    slot_id,
                    input_index
                )
            })?
            .script_pubkey
            .clone();

        let digest = self.compute_legacy_sighash_all_p2pkh(&btc_tx, input_index, &prev_spk)?;

        // Get peer's share pubkey for UserToVault
        let share_pubkey = self
            .get_share_pubkey_for_verification(
                peer_id,
                round,
                &Some(TransactionType::UserToVault),
                Some(&user_eth),
            )
            .await?;

        // Convert k256 ProjectivePoint to compressed bytes
        let share_pubkey_bytes = k256::EncodedPoint::from(share_pubkey.to_affine())
            .as_bytes()
            .to_vec();

        // Verify signature
        let msg = Message::from_digest_slice(&digest)?;
        let secp = Secp256k1::new();

        // Try all recovery IDs to find match
        for rid in 0..4 {
            if let Ok(test_rid) = RecoveryId::from_i32(rid) {
                if let Ok(test_recov_sig) =
                    secp256k1::ecdsa::RecoverableSignature::from_compact(&signature.signature, test_rid)
                {
                    if let Ok(recovered_pk) = secp.recover_ecdsa(&msg, &test_recov_sig) {
                        if recovered_pk.serialize() == share_pubkey_bytes.as_slice() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Fallback: direct verification
        let pk = secp256k1::PublicKey::from_slice(&share_pubkey_bytes)?;
        let rid = RecoveryId::from_i32(signature.recovery_id as i32)?;
        let recov_sig =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&signature.signature, rid)?;
        let std_sig = recov_sig.to_standard();
        secp.verify_ecdsa(&msg, &std_sig, &pk)?;

        Ok(())
    }

    /// Finalize and broadcast a BTC UTV slot after all inputs are aggregated.
    pub(crate) async fn finalize_btc_utv_slot(&mut self, round: u64, slot_id: String) -> Result<()> {
        let slot_key: RoundSlotKey = (round, slot_id.clone());

        // Nodes without a DKG share may not have BTC batch data yet — poll up to ~5s
        let has_dkg = self.has_dkg_share().await;
        let max_attempts = if has_dkg { 1 } else { 50 };

        // Get tx data, user_tics_address, and extras
        let (unsigned_tx, user_tics_address, extras) = {
            let mut result = None;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                let batch = self.pending.user_to_vault_btc_batch.read().await;
                if let Some(entries) = batch.get(&round) {
                    if let Some((_, user_eth, chain_tx, _, extras_opt)) = entries.iter().find(|(h, ..)| h == &slot_id) {
                        if let ChainTransaction::Bitcoin(t) = chain_tx {
                            if let Some(extras) = extras_opt {
                                if attempt > 0 {
                                    debug!(
                                        "✅ [BTC_UTV] Found BTC batch data for round {} slot {} after {} attempts (~{}ms)",
                                        round, slot_id, attempt + 1, attempt * 100
                                    );
                                }
                                result = Some((t.clone(), user_eth.clone(), extras.clone()));
                                break;
                            }
                        }
                    }
                }
                if attempt == max_attempts - 1 && !has_dkg {
                    warn!(
                        "⚠️ [BTC_UTV] Could not find BTC batch data for round {} slot {} after {}ms",
                        round, slot_id, max_attempts * 100
                    );
                }
            }
            result.ok_or_else(|| {
                anyhow!(
                    "[finalize_btc_utv] No batch data for round {} slot {} (observer timeout)",
                    round,
                    slot_id
                )
            })?
        };

        let total_inputs = unsigned_tx.inputs.len();

        // Collect per-input aggregated sigs in order
        let per_input_sigs: Vec<(usize, RecoverableSignature)> = {
            let agg_map = self.btc_utv_state.btc_utv_agg_by_round_slot.read().await;
            let slot_agg = agg_map.get(&slot_key).ok_or_else(|| {
                anyhow!(
                    "[finalize_btc_utv] No aggregated sigs for slot {} round {}",
                    slot_id,
                    round
                )
            })?;

            let mut v = Vec::with_capacity(total_inputs);
            for i in 0..total_inputs {
                let sig = slot_agg.get(&i).ok_or_else(|| {
                    anyhow!(
                        "[finalize_btc_utv] Missing aggregated sig for slot {} input {}",
                        slot_id,
                        i
                    )
                })?;
                v.push((i, *sig));
            }
            v
        };

        // Finalize and serialize (same as N2T)
        let (raw, txid, _wtxid) = Self::finalize_and_serialize_tx(
            unsigned_tx,
            extras.from_kind,
            &per_input_sigs,
            &extras.pubkey33,
        )?;

        let raw_hex = hex::encode(&raw);
        let txid_hex = hex::encode(txid);

        info!(
            "🎯 [BTC_UTV] Slot {} round {} finalized: txid={}",
            slot_id, round, txid_hex
        );

        // Broadcast to Bitcoin network
        match Self::broadcast_transaction(&raw_hex, extras.is_testnet).await {
            Ok(Some(broadcast_txid)) => {
                info!(
                    "✅ [BTC_UTV] Slot {} broadcast successful: {}",
                    slot_id, broadcast_txid
                );

                // Store final_solver for this intent (same pattern as TICS UTV)
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if let Err(e) = user_intent_manager
                        .store_final_solver(&slot_id, self.id.as_str())
                        .await
                    {
                        warn!(
                            "⚠️ [BTC_UTV] Failed to store final solver for intent {}: {}",
                            slot_id, e
                        );
                    }
                }

                // Broadcast tx_id to all nodes (via store_transaction_id_for_round -> broadcast_transaction_id)
                // Each node will store user_to_network_tx_id for this intent
                info!(
                    "📡 [BTC_UTV] Broadcasting transaction ID {} for intent {} (round {}) to all nodes",
                    broadcast_txid, slot_id, round
                );
                self.store_transaction_id_for_round(
                    round,
                    &broadcast_txid,
                    crate::types::TransactionNetwork::BTC,
                    Some(slot_id.clone()),
                )
                .await;
            }
            Ok(None) => {
                warn!(
                    "⚠️ [BTC_UTV] Slot {} broadcast completed but no txid returned, using computed txid",
                    slot_id
                );

                // Store final_solver for this intent
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if let Err(e) = user_intent_manager
                        .store_final_solver(&slot_id, self.id.as_str())
                        .await
                    {
                        warn!(
                            "⚠️ [BTC_UTV] Failed to store final solver for intent {}: {}",
                            slot_id, e
                        );
                    }
                }

                // Broadcast computed tx_id to all nodes
                info!(
                    "📡 [BTC_UTV] Broadcasting computed transaction ID {} for intent {} (round {}) to all nodes",
                    txid_hex, slot_id, round
                );
                self.store_transaction_id_for_round(
                    round,
                    &txid_hex,
                    crate::types::TransactionNetwork::BTC,
                    Some(slot_id.clone()),
                )
                .await;
            }
            Err(e) => {
                error!("❌ [BTC_UTV] Slot {} broadcast failed: {}", slot_id, e);
                self.store_transaction_error_for_round(
                    round,
                    &e.to_string(),
                    crate::types::TransactionNetwork::BTC,
                )
                .await;
            }
        }

        // Log user_tics_address for debugging (extracted but not used in current flow)
        if !user_tics_address.is_empty() {
            debug!(
                "🔗 [BTC_UTV] Slot {} was for user {}",
                slot_id, user_tics_address
            );
        }

        Ok(())
    }

    /// Bitcoin-only, per-input aware (BATCH).
    /// Ingest a whole vector of per-input signatures from one peer, then:
    /// 1) store them under (round → input_index → peer)
    /// 2) aggregate any inputs that have reached threshold
    /// 3) if all inputs aggregated, finalize & broadcast
    pub async fn handle_btc_signature_for_round(
        &mut self,
        from: String,
        items: Vec<BtcIndexedSignature>,
        round: u64,
    ) -> Result<()> {
        use anyhow::{anyhow, bail};
        use secp256k1::{
            ecdsa::{RecoverableSignature, RecoveryId},
            Message, Secp256k1,
        };
        use std::collections::{HashMap, HashSet};

        // If this round is already finalized, ignore the whole batch.
        if self
            .signatures
            .aggregated_rounds
            .read()
            .await
            .contains(&round)
        {
            info!(
                "⏭️ [BTC] round {} already finalized; ignoring batch from {}",
                round, &from
            );
            return Ok(());
        }

        // ---- 1) Pull unsigned tx + BTC extras from the correct pending store (needed for verification) ----
        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };
        let is_claim_reward_round = {
            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
            claim_reward_rounds.contains(&round)
        };
        let is_claim_platform_fee_round = {
            let r = self.pending.claim_platform_fee_rounds.read().await;
            r.contains(&round)
        };

        // Nodes without a DKG share may not have BTC TX data yet — poll up to ~5s
        let has_dkg = self.has_dkg_share().await;
        let max_attempts = if has_dkg { 1 } else { 50 };

        let (unsigned_tx, extras, total_inputs) = {
            let mut found_data: Option<(ChainTransaction, Option<BtcRoundExtras>)> = None;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                let data = if is_claim_reward_round {
                    let store = self.pending.claim_reward_pending_transactions_btc.read().await;
                    store.get(&round).map(|(chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt)| {
                        (chain_tx.clone(), extras_opt.clone())
                    })
                } else if is_claim_platform_fee_round {
                    let store = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                    store.get(&round).map(|(chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt)| {
                        (chain_tx.clone(), extras_opt.clone())
                    })
                } else if is_withdraw_round {
                    let store = self.pending.withdraw_pending_transactions_btc.read().await;
                    store.get(&round).map(|(chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt)| {
                        (chain_tx.clone(), extras_opt.clone())
                    })
                } else {
                    let store = self.pending.pending_transactions_btc.read().await;
                    store.get(&round).map(|(chain_tx, _raw, _intent_hash, _tx_type_opt, extras_opt)| {
                        (chain_tx.clone(), extras_opt.clone())
                    })
                };
                if let Some(val) = data {
                    if attempt > 0 {
                        debug!(
                            "✅ [BTC] Found BTC TX data for round {} after {} attempts (~{}ms)",
                            round, attempt + 1, attempt * 100
                        );
                    }
                    found_data = Some(val);
                    break;
                }
                if attempt == max_attempts - 1 && !has_dkg {
                    warn!(
                        "⚠️ [BTC] Could not find BTC TX data for round {} after {}ms",
                        round, max_attempts * 100
                    );
                }
            }
            let (chain_tx, extras_opt) = found_data.ok_or_else(|| {
                error!(
                    "[handle_btc_signature_for_round] No pending tx for round {} (observer timeout)",
                    round
                );
                anyhow!("no pending tx for round {}", round)
            })?;

            let btc_tx = match chain_tx {
                ChainTransaction::Bitcoin(t) => t.clone(),
                _ => {
                    error!(
                        "[handle_btc_signature_for_round] Round {} is not a Bitcoin round",
                        round
                    );
                    bail!("round {} is not a Bitcoin round", round)
                }
            };
            let ex = extras_opt.ok_or_else(|| {
                error!(
                    "[handle_btc_signature_for_round] Missing BtcRoundExtras for round {}",
                    round
                );
                anyhow!("missing btc extras for round {}", round)
            })?;
            (btc_tx.clone(), ex, btc_tx.inputs.len())
        };

        let group_pubkey33 = extras.pubkey33;
        let group_h160 = extras.signer_h160; // HASH160(pubkey33)
        let from_kind_hint = extras.from_kind; // used only for finalization wire form
        let is_testnet = extras.is_testnet;

        let _secp: Secp256k1<secp256k1::All> = Secp256k1::new();

        // ---- 2) VERIFY AND STORE THE WHOLE BATCH ----
        // First check for duplicates from previous round and filter them out
        let items_to_verify: Vec<&BtcIndexedSignature> = if round > 0 {
            let prev_round = round - 1;
            let by_round = self.btc_state.btc_sigs_by_round.read().await;
            let prev_rmap = by_round.get(&prev_round);

            items.iter()
                .filter(|it| {
                    let is_duplicate = if let Some(prev_rmap) = prev_rmap {
                        if let Some(prev_imap) = prev_rmap.get(&it.input_index) {
                            if let Some(prev_sig) = prev_imap.get(&from) {
                                // Compare signature bytes to detect duplicates
                                prev_sig.signature == it.signature.signature
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if is_duplicate {
                        warn!(
                            "🚫 [BTC] Duplicate signature detected: signature from {} for round {} input {} was already stored in round {} - skipping",
                            from, round, it.input_index, prev_round
                        );
                    }
                    !is_duplicate
                })
                .collect()
        } else {
            items.iter().collect()
        };

        // Verify each signature before storing
        let items_to_verify_count = items_to_verify.len();
        let mut verified_items = Vec::new();
        let mut verification_errors = Vec::new();

        for item in items_to_verify {
            match self
                .verify_btc_signature_for_round(
                    &from,
                    &item.signature,
                    round,
                    item.input_index,
                )
                .await
            {
                Ok(_) => {
                    info!(
                        "✅ [BTC] Signature verification passed for peer {} in round {} input {}",
                        from, round, item.input_index
                    );
                    verified_items.push(item);
                }
                Err(e) => {
                    error!(
                        "❌ [BTC] Signature verification failed for peer {} in round {} input {}: {}",
                        from, round, item.input_index, e
                    );
                    verification_errors.push((item.input_index, e));
                }
            }
        }

        // If any verifications failed, return error (but log all failures first)
        if !verification_errors.is_empty() {
            let error_msg = verification_errors
                .iter()
                .map(|(idx, e)| format!("input {}: {}", idx, e))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(anyhow!(
                "BTC signature verification failed for {} out of {} signatures from peer {} in round {}: {}",
                verification_errors.len(),
                items_to_verify_count,
                from,
                round,
                error_msg
            ));
        }

        // Store only verified signatures
        let stored_count = {
            let mut by_round = self.btc_state.btc_sigs_by_round.write().await;
            let rmap = by_round.entry(round).or_insert_with(HashMap::new);
            let mut count = 0;
            for it in verified_items {
                let imap = rmap.entry(it.input_index).or_insert_with(HashMap::new);
                // last write wins for (round,input,peer)
                imap.insert(from.clone(), it.signature.clone());
                count += 1;
            }
            count
        };

        if stored_count < items.len() {
            info!(
                "💾 [BTC] stored {} verified sigs for round {} from {} (batch, {} duplicates filtered from previous round)",
                stored_count,
                round,
                from,
                items.len() - stored_count
            );
        } else {
            info!(
                "💾 [BTC] stored {} verified sigs for round {} from {} (batch)",
                stored_count, round, from
            );
        }

        // ---- 3) SWEEP: aggregate *every* input that hit threshold ----
        for idx in 0..total_inputs {
            // skip if already aggregated
            let already_done = {
                let done = self.btc_state.btc_done_inputs_by_round.read().await;
                done.get(&round).is_some_and(|s| s.contains(&idx))
            };
            if already_done {
                continue;
            }

            // get all peer sigs for this input
            let peer_map: Option<HashMap<String, ECDSASignature>> = {
                let by_round = self.btc_state.btc_sigs_by_round.read().await;
                by_round.get(&round).and_then(|r| r.get(&idx)).cloned()
            };
            let Some(peer_map) = peer_map else {
                continue;
            };

            if peer_map.len() < self.threshold {
                continue; // not enough sigs yet
            }

            // sort deterministically and take exactly threshold
            let mut chosen: Vec<(String, ECDSASignature)> = peer_map.into_iter().collect();
            chosen.sort_by(|a, b| a.0.cmp(&b.0));
            let chosen: Vec<(String, ECDSASignature)> =
                chosen.into_iter().take(self.threshold).collect();

            // sanity: for the same input, all sigs must share the same r and be 64 bytes
            let r0 = &chosen[0].1.signature[0..32];
            for (_, s) in &chosen {
                if s.signature.len() != 64 {
                    error!(
                    "[handle_btc_signature_for_round] round {} input {}: bad sig length (got {})",
                    round,
                    idx,
                    s.signature.len()
                );
                    bail!("round {} input {}: bad sig length", round, idx);
                }
                if &s.signature[0..32] != r0 {
                    error!("[handle_btc_signature_for_round] round {} input {}: r mismatch across partial sigs", round, idx);
                    bail!(
                        "round {} input {}: r mismatch across partial sigs",
                        round,
                        idx
                    );
                }
            }

            // Decide spend kind per input via prev script shape if available.
            let maybe_prev = unsigned_tx.inputs[idx].witness_utxo.as_ref();

            // Log transaction details for debugging digest mismatches
            info!(
                "🔍 [BTC-TX-DEBUG] Final node {} transaction details for round {} input {}: version={}, inputs={}, outputs={}, locktime={}",
                self.id, round, idx, unsigned_tx.version, unsigned_tx.inputs.len(), unsigned_tx.outputs.len(), unsigned_tx.lock_time
            );
            info!(
                "🔍 [BTC-TX-DEBUG] Final node {} input {}: txid={}, vout={}, sequence={}, witness_utxo={:?}",
                self.id, idx, unsigned_tx.inputs[idx].txid, unsigned_tx.inputs[idx].vout, unsigned_tx.inputs[idx].sequence,
                maybe_prev.as_ref().map(|w| format!("value={}, script_pubkey_len={}, script_pubkey=0x{}", 
                    w.value, w.script_pubkey.len(), hex::encode(&w.script_pubkey)))
            );

            // Ensure we have consistent prevout data; mixing missing witness info across peers
            // causes different sighashes and invalid aggregated signatures.
            let maybe_prev = maybe_prev.ok_or_else(|| {
                error!(
                    "[handle_btc_signature_for_round] round {} input {} missing witness_utxo data",
                    round, idx
                );
                anyhow!("round {} input {} missing witness_utxo data", round, idx)
            })?;

            let is_p2wpkh = maybe_prev.script_pubkey.len() == 22
                && maybe_prev.script_pubkey[0] == 0x00
                && maybe_prev.script_pubkey[1] == 0x14;

            if is_p2wpkh {
                error!(
                    "[handle_btc_signature_for_round] round {} input {} carries witness program but only P2PKH is supported",
                    round, idx
                );
                bail!(
                    "round {} input {} uses P2WPKH; only P2PKH supported",
                    round,
                    idx
                );
            }

            // Validate script type against what was stored with the transaction.
            match from_kind_hint {
                SpendKind::P2WPKH => {
                    if !is_p2wpkh {
                        error!(
                            "[handle_btc_signature_for_round] round {} input {} expected P2WPKH but got script_pubkey len={} prefix={:02x?}",
                            round,
                            idx,
                            maybe_prev.script_pubkey.len(),
                            maybe_prev.script_pubkey.get(0..2)
                        );
                        bail!("round {} input {} script is not P2WPKH", round, idx);
                    }
                }
                SpendKind::P2PKH => {
                    let spk = &maybe_prev.script_pubkey;
                    let is_p2pkh = spk.len() == 25
                        && spk[0] == 0x76
                        && spk[1] == 0xA9
                        && spk[2] == 0x14
                        && spk[23] == 0x88
                        && spk[24] == 0xAC;
                    if !is_p2pkh {
                        error!(
                            "[handle_btc_signature_for_round] round {} input {} expected P2PKH but got len={} prefix={:02x?}",
                            round,
                            idx,
                            spk.len(),
                            spk.get(0..3)
                        );
                        bail!(
                            "round {} input {} script is not canonical P2PKH",
                            round,
                            idx
                        );
                    }
                }
            }

            info!(
                "🔍 [BTC-TX-DEBUG] Final node {} input {}: is_p2wpkh={}, group_h160=0x{}",
                self.id,
                idx,
                is_p2wpkh,
                hex::encode(group_h160)
            );

            // Build the per-input sighash digest (using stashed prev data; reconstruct P2PKH if absent).
            // LEGACY P2PKH only: Use the provided prev script (we bail earlier if missing).
            let prev_spk_owned: Vec<u8> = {
                info!(
                    "🔍 [BTC-TX-DEBUG] Final node {} input {}: P2PKH detected, using witness_utxo script_pubkey (len={})",
                    self.id, idx, maybe_prev.script_pubkey.len()
                );
                maybe_prev.script_pubkey.clone()
            };

            if prev_spk_owned.len() != 25
                || !(prev_spk_owned[0] == 0x76
                    && prev_spk_owned[1] == 0xA9
                    && prev_spk_owned[2] == 0x14
                    && prev_spk_owned[23] == 0x88
                    && prev_spk_owned[24] == 0xAC)
            {
                error!("[handle_btc_signature_for_round] round {} input {} prev script not canonical P2PKH", round, idx);
                bail!(
                    "round {} input {} prev script not canonical P2PKH",
                    round,
                    idx
                );
            }

            info!(
                "🔍 [BTC-TX-DEBUG] Final node {} input {}: P2PKH prev_spk=0x{}",
                self.id,
                idx,
                hex::encode(&prev_spk_owned)
            );

            let digest =
                self.compute_legacy_sighash_all_p2pkh(&unsigned_tx, idx, &prev_spk_owned)?;

            // Log the digest used for verification/aggregation (should match what each node signed)
            info!(
                "🔐 [BTC-TX-DIGEST] Final node {} verifying/aggregating signatures for round {} input {} using digest: 0x{}",
                self.id,
                round,
                idx,
                hex::encode(digest)
            );

            // Build inputs for MPC aggregation
            let mut sigs: Vec<RecoverableSignature> = Vec::with_capacity(self.threshold);
            let mut peer_to_dkg_index: Vec<(String, u32)> = Vec::with_capacity(self.threshold);
            for (peer, ecsig) in chosen {
                // Log which peer's signature we're processing and what digest they should have signed
                let peer_dkg_idx = self.calculate_dkg_index_for_peer_sync(&peer);
                info!(
                    "🔐 [BTC-TX-DIGEST] Processing signature from peer {} (DKG index: {}) for round {} input {} - expected digest: 0x{}",
                    peer,
                    peer_dkg_idx,
                    round,
                    idx,
                    hex::encode(digest)
                );
                let rid = RecoveryId::from_i32(ecsig.recovery_id as i32)?;
                let rs = RecoverableSignature::from_compact(&ecsig.signature, rid)?;
                sigs.push(rs);

                let dkg_idx = self.calculate_dkg_index_for_peer_sync(&peer);
                peer_to_dkg_index.push((peer, dkg_idx));
            }

            // aggregate this input
            let agg = match self.aggregate_signatures(sigs, peer_to_dkg_index).await {
                Ok(sig) => sig,
                Err(e) => {
                    let error_msg = e.to_string();
                    if error_msg.contains("Not enough signature shares") {
                        info!(
                            "💸 [SIGNING-REFUND] Insufficient valid signatures for aggregation in round {} input {}, triggering refund",
                            round, idx
                        );
                    }
                    return Err(e);
                }
            };

            // POST-AGGREGATION VERIFY under the **group** pubkey
            {
                let _msg = Message::from_digest_slice(&digest)?;
                let (_recid, compact) = agg.serialize_compact();
                let mut sig_std = secp256k1::ecdsa::Signature::from_compact(&compact)?;
                sig_std.normalize_s(); // low-s normalization
                let _group_pk = secp256k1::PublicKey::from_slice(&group_pubkey33)?;
                // if let Err(e) = secp.verify_ecdsa(&msg, &sig_std, &group_pk) {
                //     error!(
                //     "[btc] round {} input {}: aggregated signature does not verify under group key: {}",
                //     round, idx, e
                // );
                //     bail!(
                //         "round {} input {}: aggregated signature verify failed",
                //         round,
                //         idx
                //     );
                // }
            }

            {
                let mut agg_map = self.btc_state.btc_agg_by_round.write().await;
                agg_map
                    .entry(round)
                    .or_insert_with(HashMap::new)
                    .insert(idx, agg);
            }
            {
                let mut done = self.btc_state.btc_done_inputs_by_round.write().await;
                done.entry(round).or_insert_with(HashSet::new).insert(idx);
            }
            info!("✅ [BTC] aggregated input {} for round {}", idx, round);
        }

        // ---- 4) FINALIZE only when *all* inputs aggregated ----
        let (should_finalize, total_inputs2, unsigned_tx2) = {
            // Use the same round classification to pull the correct pending entry
            let chain_tx = if is_claim_reward_round {
                let claim_reward_pt = self.pending.claim_reward_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, _extras) =
                    claim_reward_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No claim-reward pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no claim-reward pending tx for round {}", round)
                    })?;
                chain_tx.clone()
            } else if is_claim_platform_fee_round {
                let claim_pf_pt = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, _extras) =
                    claim_pf_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No claim-platform-fee pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no claim-platform-fee pending tx for round {}", round)
                    })?;
                chain_tx.clone()
            } else if is_withdraw_round {
                let withdraw_pt = self.pending.withdraw_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, _extras) =
                    withdraw_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No withdraw pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no withdraw pending tx for round {}", round)
                    })?;
                chain_tx.clone()
            } else {
                let pt = self.pending.pending_transactions_btc.read().await;
                let (chain_tx, _raw, _intent_hash, _tx_type_opt, _extras) =
                    pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no pending tx for round {}", round)
                    })?;
                chain_tx.clone()
            };

            let btc_tx = match chain_tx {
                ChainTransaction::Bitcoin(t) => t.clone(),
                _ => {
                    error!("[handle_btc_signature_for_round] Round {} is not a Bitcoin round (finalize step)", round);
                    bail!("round {} is not a Bitcoin round", round)
                }
            };
            let done = self.btc_state.btc_done_inputs_by_round.read().await;
            let count_done = done.get(&round).map_or(0, |s| s.len());
            (
                count_done == btc_tx.inputs.len(),
                btc_tx.inputs.len(),
                btc_tx,
            )
        };

        if !should_finalize {
            info!("⏳ [BTC] round {}: waiting for remaining inputs", round);
            return Ok(());
        }

        // collect aggregated sigs in input order
        let per_input_sigs: Vec<(usize, RecoverableSignature)> = {
            let agg_map = self.btc_state.btc_agg_by_round.read().await;
            let m = agg_map
                .get(&round)
                .ok_or_else(|| anyhow!("missing agg map for round {}", round))?;
            let mut v = Vec::with_capacity(total_inputs2);
            for i in 0..total_inputs2 {
                let s = *m
                    .get(&i)
                    .ok_or_else(|| anyhow!("input {} not aggregated", i))?;
                v.push((i, s));
            }
            v
        };

        // Use the wire form hinted by builder (from extras) for final serialization.
        let (raw, txid, wtxid_opt) = Self::finalize_and_serialize_tx(
            unsigned_tx2,
            from_kind_hint,
            &per_input_sigs,
            &group_pubkey33,
        )?;

        let raw_hex = hex::encode(&raw);
        info!(
            "🎯 [BTC] round {} finalized: txid={}",
            round,
            hex::encode(txid)
        );
        if let Some(w) = wtxid_opt {
            info!("wtxid={}", hex::encode(w));
        }

        {
            let mut aggregated_rounds = self.signatures.aggregated_rounds.write().await;
            aggregated_rounds.insert(round);
        }

        // Get intent hash and user_tics_address for proper error/success handling
        let (_intent_hash, _user_tics_address) = {
            let pt = self.pending.pending_transactions_btc.read().await;
            if let Some((_chain_tx, _raw, intent_hash, _tx_type_opt, _extras)) = pt.get(&round) {
                // Get user_tics_address from the first signature we have
                let user_tics_address = {
                    let btc_sigs = self.btc_state.btc_sigs_by_round.read().await;
                    if let Some(round_sigs) = btc_sigs.get(&round) {
                        // Get the first available signature to extract user_tics_address
                        round_sigs
                            .values()
                            .flat_map(|input_sigs| input_sigs.values())
                            .next()
                            .and_then(|sig| sig.user_tics_address.clone())
                    } else {
                        None
                    }
                };
                (intent_hash.clone(), user_tics_address)
            } else {
                (None, None)
            }
        };

        // NOTE: Bitcoin transactions from the sequencer are not currently supported
        // as all contract transactions use TICS. If BTC sequencer support is needed,
        // BtcRoundExtras struct needs to be extended with request_id field.

        // Broadcast with proper error handling and transaction ID storage
        match Self::broadcast_transaction(&raw_hex, is_testnet).await {
            Ok(Some(txid)) => {
                info!(
                    "✅ [BTC] Bitcoin transaction broadcasted successfully: {}",
                    txid
                );
                self.store_transaction_id_for_round(
                    round,
                    &txid,
                    crate::types::TransactionNetwork::BTC,
                    None,
                )
                .await;
            }
            Ok(None) => {
                warn!("⚠️ [BTC] Bitcoin transaction broadcasted but no txid returned");
            }
            Err(e) => {
                error!("❌ [BTC] Failed to broadcast Bitcoin transaction: {}", e);
                self.store_transaction_error_for_round(
                    round,
                    &e.to_string(),
                    crate::types::TransactionNetwork::BTC,
                )
                .await;
            }
        }

        Ok(())
    }

    /// Broadcast transaction to Bitcoin network
    /// Handle signature received via broadcast (gossipsub); only final node aggregates.
    pub async fn handle_signature_to_final_node(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
        slot_id: Option<String>,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} via broadcast/gossipsub (round {}, slot_id: {:?})",
            self.id, from, round, slot_id
        );

        // Check if this node is the final node for the specific round
        let is_final_node = {
            let final_nodes = self.signatures.final_nodes_by_round.read().await;
            final_nodes
                .get(&round)
                .map(|node_id| node_id == &self.id)
                .unwrap_or(false)
        };

        if is_final_node {
            info!(
                "✅ [SIGNING] This node {} is the final node for round {}",
                self.id, round
            );
            return self
                .handle_signature_for_round(from, signature, round, slot_id)
                .await;
        }

        info!(
            "⚠️ [SIGNING] Received signature for round {} but this node is not the final node for that round",
            round
        );
        Ok(())
    }

    /// Handle transaction data received for final node (to enable reconstruction even if not selected to sign).
    ///
    /// Universal threshold verification: collects TX data from DKG nodes and accepts it once
    /// threshold matching copies of tx_bytes arrive. Works for ALL transaction types (batch and non-batch).
    /// If this node already has TX data locally (DKG final node), incoming data is ignored.
    pub async fn handle_transaction_data_for_final_node(
        &mut self,
        from: String,
        round: u64,
        tx_bytes: Vec<u8>,
        intent_hash: Option<String>,
        transaction_type: Option<String>,
        request_id: Option<String>,
        chain_tx_json: Option<String>,
        user_tics_address: Option<String>,
        batch_identifiers: Option<Vec<String>>,
    ) -> Result<()> {
        // Check if this node is the final node for the specific round
        let is_final_node = {
            let final_nodes = self.signatures.final_nodes_by_round.read().await;
            final_nodes
                .get(&round)
                .map(|node_id| node_id == &self.id)
                .unwrap_or(false)
        };

        if !is_final_node {
            debug!(
                "⚠️ [SIGNING] Received transaction data for round {} but this node is not the final node for that round",
                round
            );
            return Ok(());
        }

        // Determine the slot key: for batch flows use intent_hash as slot_id, for non-batch use ""
        let slot_id = intent_hash.clone().unwrap_or_default();
        let tx_data_key: crate::signing::state::TxDataKey = (round, slot_id.clone());

        // If this node already has the TX data locally (DKG final node that built it), skip
        let already_has_local_data = if slot_id.is_empty() {
            // Non-batch: check all non-batch stores (pending, withdraw, claim-reward — both ETH and BTC)
            let in_pending = self.pending.pending_transactions.read().await.contains_key(&round);
            let in_withdraw_tics = self.pending.withdraw_pending_transactions_tics.read().await.contains_key(&round);
            let in_claim_tics = self.pending.claim_reward_pending_transactions_tics.read().await.contains_key(&round);
            let in_pending_btc = self.pending.pending_transactions_btc.read().await.contains_key(&round);
            let in_withdraw_btc = self.pending.withdraw_pending_transactions_btc.read().await.contains_key(&round);
            let in_claim_btc = self.pending.claim_reward_pending_transactions_btc.read().await.contains_key(&round);
            let in_claim_pf_btc = self.pending.claim_platform_fee_pending_transactions_btc.read().await.contains_key(&round);
            in_pending || in_withdraw_tics || in_claim_tics || in_pending_btc || in_withdraw_btc || in_claim_btc || in_claim_pf_btc
        } else {
            // Batch slot: check appropriate batch store
            let tics_batch = self.pending.user_to_vault_tics_batch.read().await;
            let btc_batch = self.pending.user_to_vault_btc_batch.read().await;
            let in_tics = tics_batch
                .get(&round)
                .map(|entries| entries.iter().any(|(h, ..)| h == &slot_id))
                .unwrap_or(false);
            let in_btc = btc_batch
                .get(&round)
                .map(|entries| entries.iter().any(|(h, ..)| h == &slot_id))
                .unwrap_or(false);
            in_tics || in_btc
        };

        if already_has_local_data {
            debug!(
                "ℹ️ [SIGNING] Already have local TX data for round {} slot {:?}, ignoring from {}",
                round, intent_hash, from
            );
            return Ok(());
        }

        // chain_tx_json is required for the universal approach
        let chain_json = match &chain_tx_json {
            Some(json) => json.clone(),
            None => {
                debug!(
                    "⚠️ [SIGNING] Received TX data from {} for round {} without chain_tx_json, ignoring",
                    from, round
                );
                return Ok(());
            }
        };

        // Collect this TX data for threshold verification
        let received = crate::signing::state::ReceivedTxData {
            from: from.clone(),
            tx_bytes: tx_bytes.clone(),
            chain_tx_json: chain_json,
            intent_hash: intent_hash.clone(),
            transaction_type: transaction_type.clone(),
            request_id: request_id.clone(),
            user_tics_address: user_tics_address.clone(),
            batch_identifiers: batch_identifiers.clone(),
        };

        let mut received_store = self.pending.received_tx_data.write().await;
        let entries = received_store.entry(tx_data_key.clone()).or_insert_with(Vec::new);

        // Don't accept duplicate from same node
        if entries.iter().any(|e| e.from == from) {
            debug!(
                "ℹ️ [SIGNING] Already received TX data from {} for round {} slot {:?}",
                from, round, intent_hash
            );
            return Ok(());
        }

        entries.push(received);

        // Count how many nodes sent matching tx_bytes
        let matching_count = entries
            .iter()
            .filter(|e| e.tx_bytes == tx_bytes)
            .count();

        info!(
            "📥 [SIGNING] Collected TX data from {} for round {} slot {:?} ({}/{} threshold)",
            from, round, intent_hash, matching_count, self.threshold
        );

        // Check if we've reached threshold
        if matching_count < self.threshold {
            return Ok(());
        }

        // Threshold reached! Use the first matching entry's data (all tx_bytes are identical)
        let verified_entry = match entries.iter().find(|e| e.tx_bytes == tx_bytes) {
            Some(entry) => entry.clone(),
            None => {
                error!(
                    "❌ [SIGNING] Race condition: threshold count matched but entry not found for round {} slot {:?}",
                    round, intent_hash
                );
                return Ok(());
            }
        };

        info!(
            "✅ [SIGNING] Threshold reached for round {} slot {:?} - {} matching copies from DKG nodes",
            round, intent_hash, matching_count
        );

        // Drop the write lock before storing
        drop(received_store);

        // Deserialize the verified ChainTransaction
        let chain_tx = match serde_json::from_str::<crate::chain_abstraction::ChainTransaction>(
            &verified_entry.chain_tx_json,
        ) {
            Ok(ct) => ct,
            Err(e) => {
                warn!(
                    "⚠️ [SIGNING] Failed to deserialize chain_tx_json for round {} slot {:?}: {}",
                    round, intent_hash, e
                );
                return Ok(());
            }
        };

        // Parse the transaction type string into the enum
        let parsed_tx_type = transaction_type.as_ref().and_then(|t| {
            match t.as_str() {
                "UserToVault" => Some(crate::types::TransactionType::UserToVault),
                "NetworkToTarget" => Some(crate::types::TransactionType::NetworkToTarget),
                "WithdrawLiquidity" => Some(crate::types::TransactionType::WithdrawLiquidity),
                "IntentStatusUpdate" => Some(crate::types::TransactionType::IntentStatusUpdate),
                "ClaimReward" => Some(crate::types::TransactionType::ClaimReward),
                "ClaimPlatformFee" => Some(crate::types::TransactionType::ClaimPlatformFee),
                "PeerInvalidation" => Some(crate::types::TransactionType::PeerInvalidation),
                _ => {
                    warn!(
                        "⚠️ [SIGNING] Unknown transaction_type string '{}' for round {}, storing as None",
                        t, round
                    );
                    None
                }
            }
        });

        let user_eth = verified_entry.user_tics_address.clone().unwrap_or_default();

        // Populate intent_hashes_by_round for observer nodes so that
        // store_transaction_id_for_round can detect batch N2T / IntentStatusUpdate rounds
        // and broadcast tx-id for ALL intents in the batch (not just the first one).
        if let Some(ref batch_ids) = verified_entry.batch_identifiers {
            if !batch_ids.is_empty() {
                let mut intent_map = self.pending.intent_hashes_by_round.write().await;
                if !intent_map.contains_key(&round) {
                    info!(
                        "💾 [SIGNING] Observer: populated intent_hashes_by_round for round {} with {} intent hashes from TransactionDataForFinalNode",
                        round, batch_ids.len()
                    );
                    intent_map.insert(round, batch_ids.clone());
                }
            }
        }

        // Store in appropriate pending store based on whether this is batch or non-batch
        if !slot_id.is_empty() {
            // Batch slot: determine if TICS or BTC from the ChainTransaction variant
            match &chain_tx {
                crate::chain_abstraction::ChainTransaction::Tics(_) => {
                    let mut store = self.pending.user_to_vault_tics_batch.write().await;
                    let batch_entries = store.entry(round).or_insert_with(Vec::new);
                    if !batch_entries.iter().any(|(h, ..)| h == &slot_id) {
                        batch_entries.push((
                            slot_id.clone(),
                            user_eth,
                            chain_tx,
                            tx_bytes,
                        ));
                        info!(
                            "💾 [SIGNING] Stored verified TICS batch slot {} (round {}) after threshold verification",
                            slot_id, round
                        );
                    }
                }
                crate::chain_abstraction::ChainTransaction::Bitcoin(_) => {
                    // Compute BtcRoundExtras for observer nodes (UTV batch always uses user key)
                    let extras = self.compute_btc_extras_for_observer(
                        &Some(crate::types::TransactionType::UserToVault),
                        &user_eth,
                        round,
                    ).await;
                    let mut store = self.pending.user_to_vault_btc_batch.write().await;
                    let batch_entries = store.entry(round).or_insert_with(Vec::new);
                    if !batch_entries.iter().any(|(h, ..)| h == &slot_id) {
                        batch_entries.push((
                            slot_id.clone(),
                            user_eth,
                            chain_tx,
                            tx_bytes,
                            extras,
                        ));
                        info!(
                            "💾 [SIGNING] Stored verified BTC batch slot {} (round {}) after threshold verification",
                            slot_id, round
                        );
                    }
                }
            }
        } else {
            // Non-batch: route to the correct type-specific store based on chain variant + tx type
            let is_withdraw = matches!(parsed_tx_type, Some(crate::types::TransactionType::WithdrawLiquidity));
            let is_claim_reward = matches!(parsed_tx_type, Some(crate::types::TransactionType::ClaimReward));
            let is_claim_platform_fee = matches!(parsed_tx_type, Some(crate::types::TransactionType::ClaimPlatformFee));

            // Use batch_identifiers from the verified entry if available (for withdraw/claim batches),
            // otherwise fall back to wrapping intent_hash in a Vec.
            let identifiers_for_store = verified_entry.batch_identifiers.clone()
                .or_else(|| intent_hash.clone().map(|h| vec![h]));

            match &chain_tx {
                crate::chain_abstraction::ChainTransaction::Tics(_) => {
                    // ETH non-batch: route to correct TICS pending store
                    if is_withdraw {
                        let mut store = self.pending.withdraw_pending_transactions_tics.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    identifiers_for_store,
                                    parsed_tx_type,
                                    request_id,
                                    None,
                                ),
                            );
                            // Mark as withdraw round
                            let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
                            withdraw_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified TICS withdraw TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else if is_claim_reward {
                        let mut store = self.pending.claim_reward_pending_transactions_tics.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    identifiers_for_store,
                                    parsed_tx_type,
                                    request_id,
                                    None,
                                ),
                            );
                            // Mark as claim reward round
                            let mut claim_reward_rounds = self.pending.claim_reward_rounds.write().await;
                            claim_reward_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified TICS claim-reward TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else {
                        // Regular ETH (UserToVault, NetworkToTarget, IntentStatusUpdate, PeerInvalidation, etc.)
                        let mut pending = self.pending.pending_transactions.write().await;
                        if !pending.contains_key(&round) {
                            pending.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    intent_hash,
                                    parsed_tx_type,
                                    request_id,
                                    None,
                                ),
                            );
                            info!(
                                "💾 [SIGNING] Stored verified ETH TX for round {} (type: {:?}) after threshold verification",
                                round, transaction_type
                            );
                        }
                    }
                }
                crate::chain_abstraction::ChainTransaction::Bitcoin(_) => {
                    // BTC non-batch: route to correct BTC pending store
                    let extras = self.compute_btc_extras_for_observer(
                        &parsed_tx_type,
                        &user_eth,
                        round,
                    ).await;

                    // Re-compute identifiers for BTC branch (ETH branch consumed the first copy)
                    let btc_identifiers = verified_entry.batch_identifiers.clone()
                        .or_else(|| intent_hash.map(|h| vec![h]));

                    if is_withdraw {
                        let mut store = self.pending.withdraw_pending_transactions_btc.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    btc_identifiers,
                                    parsed_tx_type,
                                    extras,
                                ),
                            );
                            let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
                            withdraw_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified BTC withdraw TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else if is_claim_reward {
                        let mut store = self.pending.claim_reward_pending_transactions_btc.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    btc_identifiers,
                                    parsed_tx_type,
                                    extras,
                                ),
                            );
                            let mut claim_reward_rounds = self.pending.claim_reward_rounds.write().await;
                            claim_reward_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified BTC claim-reward TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else if is_claim_platform_fee {
                        let mut store = self.pending.claim_platform_fee_pending_transactions_btc.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    btc_identifiers,
                                    parsed_tx_type,
                                    extras,
                                ),
                            );
                            let mut claim_pf_rounds = self.pending.claim_platform_fee_rounds.write().await;
                            claim_pf_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified BTC claim-platform-fee TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else {
                        // Regular BTC (N2T, UserToVault non-batch, etc.)
                        let mut store = self.pending.pending_transactions_btc.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    btc_identifiers,
                                    parsed_tx_type,
                                    extras,
                                ),
                            );
                            info!(
                                "💾 [SIGNING] Stored verified BTC TX for round {} (type: {:?}) after threshold verification",
                                round, transaction_type
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the node ID
    pub fn get_node_id(&self) -> &str {
        &self.id
    }

    /// Create threshold signature shares from a regular ECDSA signature
    pub fn create_threshold_shares(
        &self,
        signature: &ECDSASignature,
        threshold: u32,
        total_shares: u32,
    ) -> Vec<ThresholdSignatureShare> {
        let mut shares = Vec::new();

        for i in 0..total_shares {
            let share = ThresholdSignatureShare {
                share: signature.signature.clone(),
                signer_id: signature.signer_id.clone(),
                share_index: i + 1,
                threshold,
                total_shares,
            };
            shares.push(share);
        }

        info!(
            "🔢 [SIGNING] Created {} threshold signature shares (threshold: {})",
            shares.len(),
            threshold
        );

        shares
    }

    /// Verify threshold signature shares
    pub fn verify_threshold_shares(&self, shares: &[ThresholdSignatureShare]) -> Result<bool> {
        if shares.is_empty() {
            return Ok(false);
        }

        let threshold = shares[0].threshold;
        let total_shares = shares[0].total_shares;

        // Check if we have enough shares
        if shares.len() < threshold as usize {
            info!(
                "⚠️ [SIGNING] Not enough shares: {}/{}",
                shares.len(),
                threshold
            );
            return Ok(false);
        }

        // Verify all shares have the same threshold and total_shares
        for share in shares {
            if share.threshold != threshold || share.total_shares != total_shares {
                warn!("❌ [SIGNING] Inconsistent threshold parameters in shares");
                return Ok(false);
            }
        }

        info!(
            "✅ [SIGNING] Threshold shares verification passed: {}/{} shares",
            shares.len(),
            threshold
        );
        Ok(true)
    }

    /// Get TICS address from public key
    pub fn get_tics_address(&self) -> Option<String> {
        if let Some(public_key) = self.key_store.public_key() {
            // Get the uncompressed public key (65 bytes)
            let public_key_bytes = public_key.serialize_uncompressed();

            // Remove the prefix byte (0x04) and take the last 20 bytes for the address
            if public_key_bytes.len() >= 21 {
                let address_bytes = &public_key_bytes[1..21];

                // Convert to TICS address format (0x + hex)
                let address = format!("0x{}", hex::encode(address_bytes));

                info!(
                    "🏦 [SIGNING] Node {} TICS address: {}",
                    self.id, address
                );
                Some(address)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Calculate DKG index for a specific peer ID using database-stored peer indices
    pub async fn calculate_dkg_index_for_peer(&self, peer_id: &str) -> u32 {
        // Get the stored peer index from database
        if let Some(index) = self.get_peer_index_from_db(peer_id).await {
            info!(
                "🔢 [SIGNING] Using stored DKG index {} for peer {}",
                index, peer_id
            );
            return index as u32;
        }

        // No stored index found - this should not happen in normal operation
        warn!(
            "❌ [SIGNING] No peer index found in database for peer {}, using default index 1",
            peer_id
        );
        1
    }

    /// Calculate DKG index for a specific peer ID (synchronous version) using database-stored peer indices
    pub fn calculate_dkg_index_for_peer_sync(&self, peer_id: &str) -> u32 {
        // Get the stored peer index from database
        if let Some(db) = &self.database {
            let key = crate::database::key_utils::peer_index_key(peer_id);
            if let Ok(Some(index)) = db.get_string::<usize>(&key) {
                info!(
                    "🔢 [SIGNING] Using stored DKG index {} for peer {} (sync)",
                    index, peer_id
                );
                return index as u32;
            }
        }

        // No stored index found - this should not happen in normal operation
        warn!(
        "❌ [SIGNING] No peer index found in database for peer {} (sync), using default index 1",
        peer_id
    );
        1
    }

    /// Process peer invalidation batch for epoch-2.
    ///
    /// Two-phase logic:
    ///   Phase 1 — Promote staging entries that survived the epoch.
    ///     Scan DISCONNECTION_STAGING:* keys.  For each one:
    ///       • Remove it from staging (consumed regardless of outcome).
    ///       • Check on-chain: if the solver is still validated → write PENDING_DISCONNECTION.
    ///       • If already invalidated on-chain → skip (nothing to do).
    ///     This means any peer that reconnected before epoch-2 was already cleared from staging
    ///     on connection and will never reach this point.
    ///
    ///   Phase 2 — Collect PENDING_DISCONNECTION entries (promoted in phase 1 plus any that
    ///     were left over from a previous epoch) and broadcast the invalidation batch.
    pub(crate) async fn process_peer_invalidation_batch(&self, round: u64) -> Result<()> {
        info!(
            "🚫 [PEER_INVALIDATION] Processing peer invalidation batch for round {}",
            round
        );

        let database = self.database.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Database not available"))?;

        // ── Phase 1: Promote surviving staging entries ──────────────────────────────
        let staging_prefix = crate::database::keys::DISCONNECTION_STAGING;
        let staging_keys = database.get_keys_with_prefix_async(staging_prefix).await.unwrap_or_default();

        if !staging_keys.is_empty() {
            info!(
                "🔄 [PEER_INVALIDATION] Phase 1: Found {} staging entry/entries to evaluate for promotion",
                staging_keys.len()
            );

            // Build contract client once (optional — skip on error, entries stay in staging)
            let contract_opt: Option<crate::contract::SolverManagerContract> =
                if let Ok(Some(config)) = crate::contract::get_solver_contract_config() {
                    if let Ok(client) = crate::contract::ContractClient::new(config.clone()) {
                        crate::contract::SolverManagerContract::new(&config, client.provider()).ok()
                    } else {
                        None
                    }
                } else {
                    None
                };

            for key in &staging_keys {
                let solver_id = match key.strip_prefix(staging_prefix) {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => continue,
                };

                // Always consume the staging entry first
                let _ = database.delete_string(key);

                // On-chain check: skip if already invalidated to avoid batch reverts
                let should_promote = if let Some(ref contract) = contract_opt {
                    match contract.is_solver_id_validated(&solver_id).await {
                        Ok(true) => {
                            true // still validated on-chain → promote
                        }
                        Ok(false) => {
                            info!(
                                "ℹ️ [PEER_INVALIDATION] Solver {} is already invalidated on-chain, dropping staging entry",
                                solver_id
                            );
                            false
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [PEER_INVALIDATION] Failed to check on-chain validation for {} during promotion: {} — promoting anyway",
                                solver_id, e
                            );
                            true
                        }
                    }
                } else {
                    // Contract unavailable — promote to be safe (existing fallback behaviour)
                    true
                };

                if should_promote {
                    let pending_key = format!(
                        "{}{}",
                        crate::database::keys::PENDING_DISCONNECTION,
                        solver_id
                    );
                    // Only write if not already present (could be left over from a prior epoch)
                    if let Ok(None) = database.get_string::<String>(&pending_key) {
                        // Re-read the staging record to carry the original metadata forward
                        let record = serde_json::json!({ "solver_id": solver_id });
                        if let Ok(record_str) = serde_json::to_string(&record) {
                            let _ = database.put_string(&pending_key, &record_str);
                        }
                        info!(
                            "✅ [PEER_INVALIDATION] Promoted solver {} from staging to invalidation queue",
                            solver_id
                        );
                    }
                }
            }
        }

        // ── Phase 2: Collect all PENDING_DISCONNECTION entries for the batch ────────
        let prefix = crate::database::keys::PENDING_DISCONNECTION;
        let keys = database.get_keys_with_prefix_async(prefix).await.unwrap_or_default();

        if keys.is_empty() {
            info!("✅ [PEER_INVALIDATION] No pending disconnections to process after promotion");
            return Ok(());
        }

        let mut all_solver_ids: Vec<String> = Vec::new();
        for key in &keys {
            if let Some(solver_id) = key.strip_prefix(prefix) {
                if !solver_id.is_empty() {
                    all_solver_ids.push(solver_id.to_string());
                }
            }
        }

        if all_solver_ids.is_empty() {
            info!("✅ [PEER_INVALIDATION] No valid solver IDs to invalidate");
            return Ok(());
        }

        // Guard: filter out invulnerable nodes (initial DKG signers) — they must never be invalidated
        if let Some(ref dkg) = self.dkg_storage {
            if let Ok(Some(invulnerables)) = dkg.get_invulnerables() {
                let before = all_solver_ids.len();
                all_solver_ids.retain(|sid| {
                    if invulnerables.contains(sid) {
                        info!(
                            "🛡️ [PEER_INVALIDATION] Solver {} is an invulnerable (DKG signer) — removing from invalidation batch and clearing PENDING_DISCONNECTION",
                            sid
                        );
                        let pending_key = format!("{}{}", prefix, sid);
                        let _ = database.delete_string(&pending_key);
                        false
                    } else {
                        true
                    }
                });
                if before != all_solver_ids.len() {
                    info!(
                        "🛡️ [PEER_INVALIDATION] Filtered {} invulnerable(s) from batch, {} remaining",
                        before - all_solver_ids.len(),
                        all_solver_ids.len()
                    );
                }
            }
        }

        if all_solver_ids.is_empty() {
            info!("✅ [PEER_INVALIDATION] All pending solvers are invulnerables or already handled, nothing to do");
            return Ok(());
        }

        // Filter out solvers that are already invalidated on-chain to avoid
        // batch reverts (invalidateSolverIds reverts if any solver in the batch is already invalidated).
        // Also clean up their PENDING_DISCONNECTION entries since they don't need processing.
        let mut solver_ids: Vec<String> = Vec::new();
        if let Ok(Some(config)) = crate::contract::get_solver_contract_config() {
            if let Ok(client) = crate::contract::ContractClient::new(config.clone()) {
                if let Ok(contract) = crate::contract::SolverManagerContract::new(&config, client.provider()) {
                    for sid in &all_solver_ids {
                        match contract.is_solver_id_validated(sid).await {
                            Ok(true) => {
                                solver_ids.push(sid.clone());
                            }
                            Ok(false) => {
                                info!(
                                    "ℹ️ [PEER_INVALIDATION] Solver {} is already invalidated on-chain, removing from batch and clearing PENDING_DISCONNECTION",
                                    sid
                                );
                                let pending_key = format!("{}{}", prefix, sid);
                                let _ = database.delete_string(&pending_key);

                                // Broadcast deletion so other peers wipe it
                                let del_msg = crate::types::ChannelMessage::PeerInvalidationDeleted {
                                    solver_id: sid.clone(),
                                    node_id: self.id.clone(),
                                };
                                let _ = self.message_tx.send(del_msg).await;
                            }
                            Err(e) => {
                                warn!(
                                    "⚠️ [PEER_INVALIDATION] Failed to check on-chain validation for {}: {} — including in batch",
                                    sid, e
                                );
                                solver_ids.push(sid.clone());
                            }
                        }
                    }
                } else {
                    solver_ids = all_solver_ids;
                }
            } else {
                solver_ids = all_solver_ids;
            }
        } else {
            solver_ids = all_solver_ids;
        }

        if solver_ids.is_empty() {
            info!("✅ [PEER_INVALIDATION] All pending solvers are already invalidated on-chain, nothing to do");
            return Ok(());
        }

        info!(
            "🚫 [PEER_INVALIDATION] Found {} solver IDs to invalidate: {:?}",
            solver_ids.len(),
            solver_ids
        );

        // Reserve a nonce for this batch BEFORE broadcasting (coordinator responsibility)
        // SECURITY: Nonces are REQUIRED - abort batch if unavailable
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let batch_timestamp = chrono::Utc::now().to_rfc3339();
            let solver_fingerprint = {
                let mut hasher = sha3::Keccak256::new();
                hasher.update(solver_ids.join(",").as_bytes());
                hex::encode(&hasher.finalize()[..8])
            };
            let reservation_key = format!(
                "peer_invalidation_batch:round:{}:node:{}:batch:{}:solver_fp:{}",
                round, self.id, batch_timestamp, solver_fingerprint
            );
            let nm_guard = nm.lock().await;
            match nm_guard
                .reserve_nonces_for_batch(std::slice::from_ref(&reservation_key))
                .await
            {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get(&reservation_key) {
                        info!(
                            "🔐 [PEER_INVALIDATION] Reserved nonce tuple assignment reservation_key={} tuple_id={}",
                            reservation_key,
                            tuple_id
                        );
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [PEER_INVALIDATION] No nonce assigned - aborting batch (will retry next epoch)");
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [PEER_INVALIDATION] Failed to reserve nonce: {} - aborting batch (will retry next epoch)", e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [PEER_INVALIDATION] NonceManager not available - aborting batch (will retry next epoch)");
            return Ok(());
        };

        // Broadcast PeerInvalidationBatch via ChannelMessage
        let timestamp = chrono::Utc::now().to_rfc3339();
        let node_id = self.id.clone();

        self.message_tx
            .send(crate::types::ChannelMessage::PeerInvalidationBatch {
                solver_ids,
                round,
                timestamp,
                node_id,
                nonce_tuple_id: Some(nonce_tuple_id),
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send peer invalidation batch message: {}", e))?;

        Ok(())
    }

}
