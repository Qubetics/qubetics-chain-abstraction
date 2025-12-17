/// Contract Transaction Sequencer
///
/// This module provides a sequencer to ensure contract transactions are executed
/// sequentially to prevent nonce collisions when multiple transactions are processed in parallel.
///
/// CRITICAL: This sequencer synchronizes processing across all nodes to prevent VRF round overlaps.
/// All nodes must process the same request at the same time using deterministic ordering.
use anyhow::Result;
use hex;
use k256::ProjectivePoint;
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::database::VrfStorage;
use crate::types::{DepositIntent, TransactionType};
use crate::vrf::service::VrfRoundSyncKind;

/// Enum to distinguish between different contract transaction flows
#[derive(Clone, Debug)]
pub enum ContractTransactionFlow {
    /// Deposit intent transactions (UserToVault, NetworkToTarget, VaultToNetwork)
    DepositIntent {
        intent: DepositIntent,
        intent_hash: String,
        transaction_type: TransactionType,
        vault_group_key: Option<ProjectivePoint>,
        amount: u128,
    },
    /// Solver operation: Add liquidity
    SolverAddLiquidity {
        solver_address: String,
        solver_id: String,
        asset_chain_name: String,
        amount: u128,
    },
    /// Solver operation: Withdraw liquidity contract update
    SolverWithdrawLiquidity {
        solver_address: String,
        asset_chain_name: String,
        amount: u128,
        payout_transaction_hash: String,
    },
    /// Solver operation: Claim reward contract update
    SolverClaimReward {
        solver_address: String,
        reward_btc: Option<u128>,
        reward_tics: Option<u128>,
        payout_transaction_hash: String,
    },
}

/// Request to execute a contract transaction
#[derive(Clone, Debug)]
pub struct ContractTransactionRequest {
    /// The type of transaction flow
    pub flow: ContractTransactionFlow,
    /// Transaction ID (unique identifier for this transaction)
    pub transaction_id: String,
    /// Sequence number for FCFS ordering (set when request is received)
    pub sequence: u64,
}

/// Sequencer synchronization state
#[derive(Clone, Debug)]
struct SequencerSyncState {
    /// Transaction ID currently being processed
    current_processing: Option<String>,
    /// Sequence number for the current processing transaction
    current_sequence: u64,
    /// Global sequence counter for FCFS ordering
    global_sequence: u64,
    /// Nodes that have agreed to process the current request
    agreed_nodes: HashSet<String>,
    /// Nodes that have confirmed completion of the current request
    confirmed_nodes: HashSet<String>,
    /// Total number of active nodes (for consensus threshold)
    total_nodes: usize,
    /// Whether current transaction is confirmed (all nodes confirmed)
    is_confirmed: bool,
    /// Transactions that were proposed before we had the full request
    missing_requests: HashSet<String>,
}

/// Sequencer for contract transactions (Vault ETH Address)
///
/// Production-ready implementation with deterministic final node selection.
/// Only the selected final node picks which request to process next.
/// Other nodes wait for the SELECT message from the final node.
///
/// CRITICAL: Final node selection is deterministic based on:
/// 1. Round number (increments after each transaction)
/// 2. Previous block hash (shared across network)
/// 3. Domain tag "VAULT" for separation from main sequencer
///
/// Flow:
/// 1. All nodes receive transaction requests (via gossip)
/// 2. Final node is selected: idx = H("VAULT" || prev_block_hash || round) mod |Nodes|
/// 3. Only final node selects next request and broadcasts SELECT message
/// 4. Other nodes verify SELECT, send ACK if they have it, or MISSING if not
/// 5. All nodes process the selected request
/// 6. Round advances for next selection
#[derive(Clone)]
pub struct ContractTransactionSequencer {
    /// Pending requests sorted by transaction_id (BTreeMap maintains sorted order)
    pending_requests: Arc<RwLock<BTreeMap<String, ContractTransactionRequest>>>,
    /// Synchronization state
    sync_state: Arc<RwLock<SequencerSyncState>>,
    /// Message channel for broadcasting sequencer sync messages
    message_tx: Option<mpsc::Sender<crate::types::ChannelMessage>>,
    /// Local node ID
    node_id: String,
    /// Cached request for the current processing transaction (set when we propose it)
    current_request_cache: Arc<RwLock<Option<ContractTransactionRequest>>>,

    // VRF + Consensus for final node selection (Vault Sequencer)
    /// Local peer ID for VRF
    local_peer_id: Option<libp2p::PeerId>,
    /// Current round number for vault sequencer (INDEPENDENT from signing rounds)
    vault_sequencer_round: Arc<RwLock<u64>>,
    /// VRF service for vault sequencer node selection (separate instance with "vault_seq:" prefix)
    vrf_service: Option<Arc<crate::protocols::VrfService>>,
    /// Consensus node for vault sequencer final node determination
    consensus_node: Option<Arc<RwLock<crate::consensus::ConsensusNode>>>,
    /// Available nodes for VRF selection
    available_nodes: Arc<RwLock<Vec<libp2p::PeerId>>>,
    /// Cache of final nodes per round (after consensus)
    final_node_cache: Arc<RwLock<HashMap<u64, libp2p::PeerId>>>,
    /// Locked request ID selected by final node (per round)
    locked_request: Arc<RwLock<Option<String>>>,
}

impl ContractTransactionSequencer {
    /// Create a new sequencer
    ///
    /// The sequencer queues contract transaction requests for sequential processing.
    /// Uses VRF + Consensus for final node selection.
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(RwLock::new(BTreeMap::new())),
            sync_state: Arc::new(RwLock::new(SequencerSyncState {
                current_processing: None,
                current_sequence: 0,
                global_sequence: 0,
                agreed_nodes: HashSet::new(),
                confirmed_nodes: HashSet::new(),
                total_nodes: 0,
                is_confirmed: false,
                missing_requests: HashSet::new(),
            })),
            message_tx: None,
            node_id: String::new(),
            current_request_cache: Arc::new(RwLock::new(None)),

            // Initialize VRF + Consensus fields
            local_peer_id: None,
            vault_sequencer_round: Arc::new(RwLock::new(0)),
            vrf_service: None,
            consensus_node: None,
            available_nodes: Arc::new(RwLock::new(Vec::new())),
            final_node_cache: Arc::new(RwLock::new(HashMap::new())),
            locked_request: Arc::new(RwLock::new(None)),
        }
    }

    /// Set local peer ID for final node selection
    pub fn set_local_peer_id(&mut self, peer_id: libp2p::PeerId) {
        self.local_peer_id = Some(peer_id);
    }

    /// Update available nodes for final node selection
    pub async fn update_available_nodes(&self, nodes: Vec<libp2p::PeerId>) {
        let mut available = self.available_nodes.write().await;
        *available = nodes;
        info!(
            "🔄 [VAULT_SEQUENCER] Updated available nodes: count={}",
            available.len()
        );
    }

    /// Select final node deterministically for current round using VRF + Consensus
    /// Returns the peer ID of the selected node (from consensus cache)
    async fn select_final_node(&self) -> Result<libp2p::PeerId> {
        let round = *self.vault_sequencer_round.read().await;

        // Check if consensus has completed for this round
        let cache = self.final_node_cache.read().await;
        if let Some(final_node) = cache.get(&round) {
            return Ok(*final_node);
        }

        // Consensus not complete yet
        Err(anyhow::anyhow!(
            "Consensus not complete for vault sequencer round {}. Run VRF selection and consensus first.",
            round
        ))
    }

    /// Perform VRF node selection for current round
    pub async fn perform_vrf_selection(&self, threshold: usize) -> Result<()> {
        info!("🚦 [VAULT_SEQUENCER] Starting VRF round sync before selection");
        let round = self.sync_round_with_peers().await?;
        info!(
            "🔁 [VAULT_SEQUENCER] VRF round sync completed, proceeding with selection: round={}",
            round
        );
        let nodes = self.available_nodes.read().await.clone();

        if nodes.is_empty() {
            return Err(anyhow::anyhow!("No available nodes for VRF selection"));
        }

        info!(
            "🎯 [VAULT_SEQUENCER] Starting VRF selection for round {} with {} nodes",
            round,
            nodes.len()
        );

        if let Some(vrf_service) = &self.vrf_service {
            // Perform VRF selection (separate storage via prefix)
            let selection_result = vrf_service
                .perform_node_selection_without_broadcast(
                    &nodes,
                    threshold,
                    round,
                    "vault_sequencer",
                )
                .await?;

            info!(
                "✅ [VAULT_SEQUENCER] VRF selection completed for round {}: {} nodes selected",
                round,
                selection_result.selected_nodes.len()
            );

            // Create broadcast with vault sequencer specific message type
            if let Some(broadcast_msg) = vrf_service.create_broadcast_for_round(round).await {
                if let Some(message_tx) = &self.message_tx {
                    let broadcast_data = serde_json::to_vec(
                        &crate::types::GossipsubMessage::VaultSequencerVrfSelectedNodes(
                            broadcast_msg,
                        ),
                    )?;

                    message_tx
                        .send(crate::types::ChannelMessage::Broadcast {
                            topic: "vault-sequencer-vrf".to_string(),
                            data: broadcast_data,
                        })
                        .await?;

                    info!(
                        "📤 [VAULT_SEQUENCER] Broadcasted VRF selection for round {}",
                        round
                    );
                }
            }
        } else {
            return Err(anyhow::anyhow!("VRF service not available"));
        }

        Ok(())
    }

    pub async fn sync_round_with_peers(&self) -> Result<u64> {
        if let Some(vrf_service) = &self.vrf_service {
            let round = *self.vault_sequencer_round.read().await;
            vrf_service.set_current_round(round).await;
            let synced_round = vrf_service
                .sync_rounds(VrfRoundSyncKind::VaultSequencer)
                .await?;

            let mut local_round = self.vault_sequencer_round.write().await;
            *local_round = synced_round;
            Ok(synced_round)
        } else {
            Ok(*self.vault_sequencer_round.read().await)
        }
    }

    /// Check if we have enough VRF selections to start consensus
    pub async fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        if let Some(vrf_service) = &self.vrf_service {
            vrf_service.can_start_consensus(round, min_selections).await
        } else {
            false
        }
    }

    /// Start consensus to determine final node for current round
    pub async fn start_consensus(&self, round: u64) -> Result<crate::types::ConsensusResult> {
        info!(
            "🎯 [VAULT_SEQUENCER] Starting consensus for round {}",
            round
        );

        // Get VRF-selected nodes from VRF service
        let selected_nodes = if let Some(vrf_service) = &self.vrf_service {
            vrf_service
                .get_all_selected_nodes_with_frequencies(round)
                .await
        } else {
            return Err(anyhow::anyhow!("VRF service not available"));
        };

        if selected_nodes.is_empty() {
            return Err(anyhow::anyhow!(
                "No VRF selections available for vault sequencer round {}",
                round
            ));
        }

        info!(
            "📊 [VAULT_SEQUENCER] Got {} VRF selections for round {}",
            selected_nodes.len(),
            round
        );

        // Run consensus algorithm
        if let Some(consensus) = &self.consensus_node {
            let mut consensus_node = consensus.write().await;
            consensus_node.add_selected_nodes(round, selected_nodes);

            let result = consensus_node.start_consensus(round)?;

            info!(
                "✅ [VAULT_SEQUENCER] Consensus completed for round {}: final node = {:?}",
                round, result.final_node
            );

            // Cache final node for this round
            let mut cache = self.final_node_cache.write().await;
            cache.insert(round, result.final_node.0);

            Ok(result)
        } else {
            Err(anyhow::anyhow!("Consensus node not available"))
        }
    }

    /// Check if current node is the final node for this round
    pub async fn am_i_final_node(&self) -> Result<bool> {
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        let final_node = self.select_final_node().await?;
        Ok(local_peer == final_node)
    }

    /// Advance to next round
    pub async fn advance_round(&self) {
        let mut round = self.vault_sequencer_round.write().await;
        *round += 1;

        // Clear locked request
        let mut locked = self.locked_request.write().await;
        *locked = None;

        info!("📈 [VAULT_SEQUENCER] Advanced to round {}", *round);
    }

    /// Get current round
    pub async fn get_current_round(&self) -> u64 {
        *self.vault_sequencer_round.read().await
    }

    /// Set VRF service for vault sequencer
    pub fn set_vrf_service(&mut self, vrf_service: Arc<crate::protocols::VrfService>) {
        self.vrf_service = Some(vrf_service);
        info!("🔧 [VAULT_SEQUENCER] VRF service configured");
    }

    /// Access underlying VRF service (read-only) for vault sequencer
    pub fn vrf_service(&self) -> Option<&crate::protocols::VrfService> {
        self.vrf_service.as_deref()
    }

    pub fn vrf_storage(&self) -> Option<VrfStorage> {
        self.vrf_service
            .as_ref()
            .and_then(|service| service.storage())
    }

    /// Set consensus node for vault sequencer
    pub fn set_consensus_node(&mut self, consensus: Arc<RwLock<crate::consensus::ConsensusNode>>) {
        self.consensus_node = Some(consensus);
        info!("🔧 [VAULT_SEQUENCER] Consensus node configured");
    }

    /// Handle VRF selected nodes broadcast from another node
    pub async fn handle_vrf_broadcast(
        &self,
        broadcast: crate::protocols::VrfSelectedNodesBroadcast,
        total_nodes: usize,
    ) -> Result<()> {
        if let Some(vrf_service) = &self.vrf_service {
            vrf_service
                .handle_vrf_broadcast(broadcast, total_nodes)
                .await;
            info!("✅ [VAULT_SEQUENCER] Handled VRF broadcast");
        } else {
            warn!("⚠️ [VAULT_SEQUENCER] VRF service not available for handling broadcast");
        }
        Ok(())
    }

    /// Check and trigger consensus if enough VRF selections received
    pub async fn check_and_trigger_consensus(
        &self,
        round: u64,
        min_selections: usize,
    ) -> Result<Option<crate::types::ConsensusResult>> {
        if self.can_start_consensus(round, min_selections).await {
            info!(
                "🎯 [VAULT_SEQUENCER] Enough VRF selections for round {}, starting consensus",
                round
            );

            match self.start_consensus(round).await {
                Ok(result) => {
                    info!(
                        "✅ [VAULT_SEQUENCER] Consensus complete for round {}: final node = {:?}",
                        round, result.final_node
                    );
                    Ok(Some(result))
                }
                Err(e) => {
                    error!(
                        "❌ [VAULT_SEQUENCER] Failed to start consensus for round {}: {}",
                        round, e
                    );
                    Err(e)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Generate a deterministic transaction ID for add_liquidity operations
    ///
    /// Uses Keccak256 hash of operation parameters to ensure all nodes generate the same ID.
    /// For deposit intents, the transaction_id should be the actual tx_hash from the blockchain.
    ///
    /// **IMPORTANT**: This function generates a base transaction_id from operation parameters.
    /// To ensure uniqueness in the sequencer queue, the sequencer will append the sequence number
    /// to the transaction_id when inserting into the queue (if a duplicate is detected).
    ///
    /// # Parameters
    /// - `solver_address`: Solver's address
    /// - `solver_id`: Solver ID
    /// - `asset_chain_name`: Asset chain name
    /// - `amount`: Amount
    /// - `request_id`: Unique request ID (timestamp + solver_id) for uniqueness
    pub fn generate_transaction_id_for_add_liquidity(
        solver_address: &str,
        solver_id: &str,
        asset_chain_name: &str,
        amount: u128,
        request_id: &str,
    ) -> String {
        // Create a deterministic string representation for add_liquidity
        // request_id ensures uniqueness for each request
        let data = format!(
            "add_liquidity:{}:{}:{}:{}:{}",
            solver_address, solver_id, asset_chain_name, amount, request_id
        );

        // Hash using Keccak256 (same as Ethereum)
        let hash = Keccak256::digest(data.as_bytes());
        format!("0x{}", hex::encode(hash))
    }

    /// Generate a deterministic transaction ID for withdraw_liquidity contract updates
    ///
    /// Uses Keccak256 hash of solver, chain, amount, payout tx hash, and request_id to ensure
    /// all nodes derive the same ID. `request_id` can be any stable identifier (e.g., payout
    /// tx hash or timestamp+solver) that is shared across nodes.
    pub fn generate_transaction_id_for_withdraw_liquidity(
        solver_address: &str,
        asset_chain_name: &str,
        amount: u128,
        payout_tx_hash: &str,
    ) -> String {
        let data = format!(
            "withdraw_liquidity:{}:{}:{}:{}",
            solver_address, asset_chain_name, amount, payout_tx_hash
        );

        let hash = Keccak256::digest(data.as_bytes());
        format!("0x{}", hex::encode(hash))
    }

    /// Generate a deterministic transaction ID for claim_reward contract updates
    ///
    /// Uses Keccak256 hash of solver, reward amounts, and payout tx hash to ensure
    /// all nodes derive the same ID.
    pub fn generate_transaction_id_for_claim_reward(
        solver_address: &str,
        reward_btc: Option<u128>,
        reward_tics: Option<u128>,
        payout_tx_hash: &str,
    ) -> String {
        let data = format!(
            "claim_reward:{}:{}:{}:{}",
            solver_address,
            reward_btc.unwrap_or(0),
            reward_tics.unwrap_or(0),
            payout_tx_hash
        );

        let hash = Keccak256::digest(data.as_bytes());
        format!("0x{}", hex::encode(hash))
    }

    /// Initialize the sequencer with network components
    pub async fn initialize(
        &mut self,
        message_tx: mpsc::Sender<crate::types::ChannelMessage>,
        node_id: String,
        total_nodes: usize,
    ) {
        self.message_tx = Some(message_tx);
        self.node_id = node_id.clone();
        let mut state = self.sync_state.write().await;
        state.total_nodes = total_nodes;
        info!(
            "✅ [SEQUENCER] Initialized node {} with {} total nodes (FCFS ordering enabled)",
            node_id, total_nodes
        );
    }

    /// Submit a contract transaction request to the sequencer (FCFS - First Come First Served)
    ///
    /// CRITICAL: All nodes must receive the same requests in the same order.
    /// This is ensured by the network layer broadcasting requests to all nodes.
    pub async fn submit(&self, mut request: ContractTransactionRequest) -> Result<()> {
        let transaction_id = request.transaction_id.clone();

        // Generate a description for logging based on flow type
        let flow_description = match &request.flow {
            ContractTransactionFlow::DepositIntent { intent_hash, .. } => {
                format!("deposit_intent:{}", intent_hash)
            }
            ContractTransactionFlow::SolverAddLiquidity {
                solver_address,
                asset_chain_name,
                amount,
                ..
            } => {
                format!(
                    "solver_add_liquidity:{}:{}:{}",
                    solver_address, asset_chain_name, amount
                )
            }
            ContractTransactionFlow::SolverWithdrawLiquidity {
                solver_address,
                asset_chain_name,
                amount,
                payout_transaction_hash,
                ..
            } => {
                format!(
                    "solver_withdraw_liquidity:{}:{}:{}:{}",
                    solver_address, asset_chain_name, amount, payout_transaction_hash
                )
            }
            ContractTransactionFlow::SolverClaimReward {
                solver_address,
                reward_btc,
                reward_tics,
                payout_transaction_hash,
                ..
            } => {
                format!(
                    "solver_claim_reward:{}:{}:{}:{}",
                    solver_address,
                    reward_btc.unwrap_or(0),
                    reward_tics.unwrap_or(0),
                    payout_transaction_hash
                )
            }
        };

        // CRITICAL: Hold both locks together to ensure atomic sequence assignment and queue insertion
        // This prevents race conditions where:
        // 1. Multiple requests could get the same sequence (prevented by sync_state lock)
        // 2. Requests could be added to queue out of sequence order (prevented by holding both locks)
        let (was_waiting, final_transaction_id) = {
            // First, acquire both locks to ensure atomicity
            let mut sync_state = self.sync_state.write().await;
            let mut pending = self.pending_requests.write().await;

            // Assign sequence number (atomic operation)
            sync_state.global_sequence += 1;
            request.sequence = sync_state.global_sequence;
            let sequence = sync_state.global_sequence;

            // Ensure transaction_id uniqueness: if a duplicate exists, append sequence number
            let final_transaction_id = if pending.contains_key(&transaction_id) {
                // Duplicate detected: append sequence to make it unique
                let unique_id = format!("{}:seq{}", transaction_id, sequence);
                warn!(
                    "⚠️ [SEQUENCER] Duplicate transaction_id detected: {}. Using unique ID: {}",
                    transaction_id, unique_id
                );
                unique_id
            } else {
                transaction_id.clone()
            };

            // Update the request's transaction_id to the final (potentially unique) ID
            request.transaction_id = final_transaction_id.clone();

            // Add to pending requests (BTreeMap maintains sorted order by transaction_id)
            // This happens atomically with sequence assignment
            let final_tx_id_for_log = final_transaction_id.clone();
            let was_waiting = sync_state.missing_requests.contains(&final_transaction_id);
            pending.insert(final_transaction_id.clone(), request);
            let queue_size = pending.len();

            info!(
                "📥 [SEQUENCER] [DETERMINISTIC] Queued transaction: tx_id={}, flow={}, sequence={}, queue_size={}",
                final_tx_id_for_log, flow_description, sequence, queue_size
            );
            info!(
                "📋 [SEQUENCER] [DETERMINISTIC] Queue state (sorted by tx_id): {:?}",
                pending
                    .iter()
                    .map(|(tx_id, r)| (tx_id.clone(), r.sequence))
                    .collect::<Vec<_>>()
            );

            (was_waiting, final_transaction_id)
        }; // Both locks released here

        // If we were waiting for this request, trigger the re-agreement logic
        if was_waiting {
            // The wait_for_missing_request_and_reagree task will pick it up
            info!(
                "✅ [SEQUENCER] [SYNC] Request {} arrived, wait task will handle agreement",
                final_transaction_id
            );
        }

        Ok(())
    }

    /// Get the current processing transaction info (if any)
    /// Returns (tx_id, sequence, is_confirmed) if we're processing something
    pub async fn get_current_processing(&self) -> Option<(String, u64, bool)> {
        let sync_state = self.sync_state.read().await;
        if let Some(tx_id) = &sync_state.current_processing {
            Some((
                tx_id.clone(),
                sync_state.current_sequence,
                sync_state.is_confirmed,
            ))
        } else {
            None
        }
    }

    /// Get the request for the current processing transaction
    /// First checks the cache (if we proposed it), then checks the queue (if we received a "proposed" message)
    pub async fn get_current_request(&self) -> Option<ContractTransactionRequest> {
        // First, check if we have it cached (we proposed it)
        {
            let cache = self.current_request_cache.read().await;
            if let Some(request) = cache.as_ref().cloned() {
                info!(
                    "🎯 [SEQUENCER] [FCFS] Retrieved current request from cache: tx_id={}, sequence={}",
                    request.transaction_id, request.sequence
                );
                return Some(request);
            }
        }

        // If not in cache, try to get it from the queue (we received a "proposed" message)
        let sync_state = self.sync_state.read().await;
        let current_tx = sync_state.current_processing.clone();
        drop(sync_state);

        if let Some(tx_id) = current_tx {
            // Get the request from the queue (BTreeMap lookup by transaction_id)
            let mut pending = self.pending_requests.write().await;
            if let Some(request) = pending.remove(&tx_id) {
                info!(
                    "🎯 [SEQUENCER] [DETERMINISTIC] Retrieved current request from queue: tx_id={}, sequence={}",
                    request.transaction_id, request.sequence
                );
                Some(request)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Check if the local node has confirmed the current processing transaction
    pub async fn is_locally_confirmed(&self) -> bool {
        let sync_state = self.sync_state.read().await;
        sync_state.confirmed_nodes.contains(&self.node_id)
    }

    /// Get the next request to process based on final node selection
    /// Only the final node selects the request, others wait for SELECT message
    /// Returns None if something is currently being processed or not confirmed yet
    pub async fn get_next_request(&self) -> Option<ContractTransactionRequest> {
        let sync_state = self.sync_state.read().await;

        // CRITICAL: Don't move to next until previous is confirmed by all nodes
        if let Some(current_tx) = &sync_state.current_processing {
            if !sync_state.is_confirmed {
                info!(
                    "⏳ [VAULT_SEQUENCER] Waiting for confirmation: current_tx={}, confirmed_nodes={}/{}, is_confirmed={}",
                    current_tx,
                    sync_state.confirmed_nodes.len(),
                    sync_state.total_nodes,
                    sync_state.is_confirmed
                );
                return None;
            }
            info!(
                "✅ [VAULT_SEQUENCER] Previous transaction {} confirmed, ready for next",
                current_tx
            );
        }

        drop(sync_state);

        // Small delay to allow VRF round sync and broadcasts to propagate
        // before selecting the next request. This helps keep sequencer rounds
        // aligned across nodes in parallel transaction scenarios.
        tokio::time::sleep(tokio::time::Duration::from_millis(3000)).await;

        // Check if there's a locked request (selected by final node)
        {
            let locked = self.locked_request.read().await;
            if let Some(request_id) = &*locked {
                // We have a locked request from final node - retrieve and return it
                let mut pending = self.pending_requests.write().await;
                if let Some(request) = pending.remove(request_id) {
                    info!(
                        "🔓 [VAULT_SEQUENCER] Processing locked request from final node: {}",
                        request_id
                    );
                    return Some(request);
                }
            }
        }

        // Check if we have pending requests
        let queue_len = {
            let pending = self.pending_requests.read().await;
            pending.len()
        };

        if queue_len == 0 {
            return None;
        }

        info!(
            "📤 [VAULT_SEQUENCER] Dequeue next transaction attempt: queue_len={}, round={}",
            queue_len,
            *self.vault_sequencer_round.read().await
        );

        // Get current round and check if consensus is complete
        let round = *self.vault_sequencer_round.read().await;
        let cache = self.final_node_cache.read().await;
        let has_final_node = cache.contains_key(&round);
        drop(cache);

        if !has_final_node {
            // Consensus not complete - trigger VRF if not already done
            // This matches signing module pattern: perform VRF when starting to process
            info!(
                "🎯 [VAULT_SEQUENCER] No final node for round {}, triggering VRF selection",
                round
            );

            // Get available nodes
            let nodes = self.available_nodes.read().await.clone();
            if nodes.is_empty() {
                warn!("⚠️ [VAULT_SEQUENCER] No available nodes for VRF selection");
                return None;
            }

            info!(
                "🔍 [VAULT_SEQUENCER] Available nodes for VRF: count={}, nodes={:?}",
                nodes.len(),
                nodes.iter().map(|p| p.to_string()).collect::<Vec<_>>()
            );

            // Check if VRF service is available
            if self.vrf_service.is_none() {
                error!(
                    "❌ [VAULT_SEQUENCER] VRF service not configured! Cannot perform selection."
                );
                return None;
            }

            // Trigger VRF selection (matches signing module: spawn async to avoid blocking)
            let threshold = nodes.len(); // All nodes must participate
            let sequencer_clone = self.clone();
            tokio::spawn(async move {
                info!(
                    "🚀 [VAULT_SEQUENCER] Starting VRF selection task for round {}",
                    round
                );
                if let Err(e) = sequencer_clone.perform_vrf_selection(threshold).await {
                    error!("❌ [VAULT_SEQUENCER] VRF selection failed: {}", e);
                } else {
                    info!(
                        "✅ [VAULT_SEQUENCER] VRF selection task completed for round {}",
                        round
                    );
                }
            });

            // Return None - consensus will complete after VRF broadcasts are collected
            return None;
        }

        // Consensus complete - check if we are the final node
        match self.am_i_final_node().await {
            Ok(true) => {
                // We are the final node - select the request
                let mut pending = self.pending_requests.write().await;
                if let Some((tx_id, request)) = pending.pop_first() {
                    let sequence = request.sequence;
                    let queue_size = pending.len();
                    info!(
                        "🎯 [VAULT_SEQUENCER] Final node selecting request: tx_id={}, sequence={}, remaining={}",
                        tx_id, sequence, queue_size
                    );

                    // Lock this request
                    drop(pending);
                    let mut locked = self.locked_request.write().await;
                    *locked = Some(tx_id.clone());

                    // Broadcast SELECT message
                    if let Err(e) = self.broadcast_select_message(&tx_id, &request).await {
                        warn!("⚠️ [VAULT_SEQUENCER] Failed to broadcast SELECT: {}", e);
                    }

                    drop(locked);
                    Some(request)
                } else {
                    None
                }
            }
            Ok(false) => {
                // We are NOT the final node - wait for SELECT message
                None
            }
            Err(e) => {
                warn!(
                    "⚠️ [VAULT_SEQUENCER] Error checking final node status: {}",
                    e
                );
                None
            }
        }
    }

    /// Broadcast SELECT message (called by final node only)
    async fn broadcast_select_message(
        &self,
        request_id: &str,
        request: &ContractTransactionRequest,
    ) -> Result<()> {
        let round = *self.vault_sequencer_round.read().await;
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        // Helpful context for debugging which flow is being selected
        let flow_label = match &request.flow {
            ContractTransactionFlow::DepositIntent {
                intent_hash,
                transaction_type,
                amount,
                ..
            } => {
                format!(
                    "DepositIntent(intent_hash={}, type={:?}, amount={})",
                    intent_hash, transaction_type, amount
                )
            }
            ContractTransactionFlow::SolverAddLiquidity {
                solver_address,
                solver_id,
                asset_chain_name,
                amount,
            } => {
                format!(
                    "SolverAddLiquidity(solver={}, solver_id={}, chain={}, amount={})",
                    solver_address, solver_id, asset_chain_name, amount
                )
            }
            ContractTransactionFlow::SolverWithdrawLiquidity {
                solver_address,
                asset_chain_name,
                amount,
                payout_transaction_hash,
            } => {
                format!(
                    "SolverWithdrawLiquidity(solver={}, chain={}, amount={}, payout_tx={})",
                    solver_address, asset_chain_name, amount, payout_transaction_hash
                )
            }
            ContractTransactionFlow::SolverClaimReward {
                solver_address,
                reward_btc,
                reward_tics,
                payout_transaction_hash,
            } => {
                format!(
                    "SolverClaimReward(solver={}, btc={:?}, tics={:?}, payout_tx={})",
                    solver_address, reward_btc, reward_tics, payout_transaction_hash
                )
            }
        };

        info!(
            "📤 [VAULT_SEQUENCER] Broadcasting SELECT: round={}, request_id={}, flow={}",
            round, request_id, flow_label
        );

        // Create signature (simplified - in production use proper signing)
        let signature = vec![]; // TODO: Sign with node's private key

        // Broadcast via message channel
        if let Some(tx) = &self.message_tx {
            let msg = crate::types::ChannelMessage::Broadcast {
                topic: "vault-sequencer-select".to_string(),
                data: serde_json::to_vec(&crate::types::GossipsubMessage::VaultSequencerSelect {
                    round,
                    request_id: request_id.to_string(),
                    final_node_id: local_peer,
                    signature,
                })?,
            };

            tx.send(msg)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send SELECT: {}", e))?;
        }

        Ok(())
    }

    /// Broadcast ACK message
    async fn broadcast_ack(&self, request_id: &str) -> Result<()> {
        let round = *self.vault_sequencer_round.read().await;
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        if let Some(tx) = &self.message_tx {
            let msg = crate::types::ChannelMessage::Broadcast {
                topic: "vault-sequencer-ack".to_string(),
                data: serde_json::to_vec(&crate::types::GossipsubMessage::VaultSequencerAck {
                    round,
                    request_id: request_id.to_string(),
                    node_id: local_peer,
                })?,
            };

            tx.send(msg)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send ACK: {}", e))?;
        }

        Ok(())
    }

    /// Broadcast MISSING message
    async fn broadcast_missing(&self, request_id: &str) -> Result<()> {
        let round = *self.vault_sequencer_round.read().await;
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        if let Some(tx) = &self.message_tx {
            let msg = crate::types::ChannelMessage::Broadcast {
                topic: "vault-sequencer-missing".to_string(),
                data: serde_json::to_vec(&crate::types::GossipsubMessage::VaultSequencerMissing {
                    round,
                    request_id: request_id.to_string(),
                    node_id: local_peer,
                })?,
            };

            tx.send(msg)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send MISSING: {}", e))?;
        }

        Ok(())
    }

    /// Handle SELECT message from final node
    pub async fn handle_select_message(
        &self,
        round: u64,
        request_id: String,
        final_node_id: libp2p::PeerId,
    ) -> Result<()> {
        let current_round = *self.vault_sequencer_round.read().await;

        if round != current_round {
            warn!(
                "⚠️ [VAULT_SEQUENCER] SELECT message for wrong round: expected={}, got={}",
                current_round, round
            );
            return Ok(());
        }

        // Verify the sender is actually the final node
        let expected_final = self.select_final_node().await?;
        if final_node_id != expected_final {
            warn!(
                "⚠️ [VAULT_SEQUENCER] SELECT from non-final node: expected={:?}, got={:?}",
                expected_final, final_node_id
            );
            return Ok(());
        }

        // Lock this request
        let mut locked = self.locked_request.write().await;
        *locked = Some(request_id.clone());

        info!(
            "🔒 [VAULT_SEQUENCER] Locked request from final node: round={}, request_id={}",
            round, request_id
        );

        // Check if we have this request
        let pending = self.pending_requests.read().await;
        let has_request = pending.contains_key(&request_id);
        drop(pending);

        if has_request {
            info!(
                "✅ [VAULT_SEQUENCER] Have request, sending ACK: {}",
                request_id
            );
            self.broadcast_ack(&request_id).await?;
        } else {
            warn!(
                "⚠️ [VAULT_SEQUENCER] Missing request, sending MISSING: {}",
                request_id
            );
            self.broadcast_missing(&request_id).await?;

            // Wait for request to arrive
            info!(
                "⏳ [VAULT_SEQUENCER] Waiting for missing request: {}",
                request_id
            );
            self.wait_for_request(&request_id, round).await?;
        }

        Ok(())
    }

    /// Handle ACK for a SELECT message to track agreement progress
    pub async fn handle_select_ack(&self, round: u64, request_id: &str, node_id: libp2p::PeerId) {
        let current_round = *self.vault_sequencer_round.read().await;

        if round != current_round {
            warn!(
                "⚠️ [VAULT_SEQUENCER] ACK for wrong round: expected={}, got={}",
                current_round, round
            );
            return;
        }

        let mut sync_state = self.sync_state.write().await;

        // Only track ACKs for the currently processing or locked request
        let is_for_current = sync_state
            .current_processing
            .as_ref()
            .map(|tx| tx == request_id)
            .unwrap_or(false);

        let is_locked = {
            let locked = self.locked_request.read().await;
            locked.as_deref() == Some(request_id)
        };

        if !is_for_current && !is_locked {
            info!(
                "ℹ️ [VAULT_SEQUENCER] Ignoring ACK for unrelated request: {} (current={:?}, locked={})",
                request_id,
                sync_state.current_processing,
                is_locked
            );
            return;
        }

        let node_id_str = node_id.to_string();
        if sync_state.agreed_nodes.insert(node_id_str.clone()) {
            info!(
                "✅ [VAULT_SEQUENCER] ACK recorded: request_id={}, from={}, agreed: {}/{} (threshold: {})",
                request_id,
                node_id_str,
                sync_state.agreed_nodes.len(),
                sync_state.total_nodes,
                (sync_state.total_nodes / 2) + 1
            );
        } else {
            info!(
                "🔄 [VAULT_SEQUENCER] Duplicate ACK ignored for request_id={} from {}",
                request_id, node_id_str
            );
        }
    }

    /// Wait for a missing request to arrive (with timeout)
    async fn wait_for_request(&self, request_id: &str, round: u64) -> Result<()> {
        let timeout_ms = 5000; // 5 seconds timeout
        let check_interval_ms = 100; // Check every 100ms

        let start = std::time::Instant::now();

        while start.elapsed().as_millis() < timeout_ms as u128 {
            // Check if request has arrived
            let pending = self.pending_requests.read().await;
            if pending.contains_key(request_id) {
                drop(pending);

                info!(
                    "✅ [VAULT_SEQUENCER] Missing request {} arrived!",
                    request_id
                );

                // Send ACK now that we have it
                self.broadcast_ack(request_id).await?;

                return Ok(());
            }
            drop(pending);

            // Wait a bit before checking again
            tokio::time::sleep(tokio::time::Duration::from_millis(check_interval_ms)).await;
        }

        // Timeout - request never arrived
        warn!(
            "⏱️ [VAULT_SEQUENCER] Timeout waiting for request {} (round {}), skipping",
            request_id, round
        );

        Ok(())
    }

    /// Handle sequencer sync message from another node
    pub async fn handle_sync_message(
        &self,
        transaction_id: String,
        sequence: u64,
        node_id: String,
        state: String,
    ) {
        let mut sync_state = self.sync_state.write().await;

        info!(
            "📨 [SEQUENCER] [SYNC] Received sync message: node={}, tx_id={}, sequence={}, state={}, current_tx={:?}",
            node_id, transaction_id, sequence, state, sync_state.current_processing
        );

        // If this is a "proposed" message, add the node to agreed nodes
        if state == "proposed" || state == "processing" {
            let mut missing_at_proposal = false;
            // Check if this is the transaction we're currently processing (or should be processing)
            let should_agree = if sync_state.current_processing.as_ref() == Some(&transaction_id) {
                // We're already processing this transaction
                true
            } else if sync_state.current_processing.is_none() {
                // We haven't proposed anything yet - check if we have this transaction in our queue
                // CRITICAL: Get and remove the request atomically to prevent race conditions
                // Drop sync_state lock first to avoid deadlock
                drop(sync_state);
                let mut pending = self.pending_requests.write().await;
                if let Some(request) = pending.remove(&transaction_id) {
                    // We found and removed the request - now set it as current_processing and agree
                    drop(pending);

                    // Cache the request immediately so we can retrieve it later
                    let mut cache = self.current_request_cache.write().await;
                    *cache = Some(request.clone());
                    drop(cache);

                    info!(
                        "🔄 [SEQUENCER] [SYNC] We have tx_id={} in queue but haven't proposed yet. Setting as current_processing and agreeing.",
                        transaction_id
                    );

                    // Re-acquire sync_state lock and update state
                    sync_state = self.sync_state.write().await;
                    sync_state.current_processing = Some(transaction_id.clone());
                    sync_state.current_sequence = sequence;
                    // DON'T clear agreed_nodes here - other nodes may have already agreed!
                    // Only clear confirmed_nodes and is_confirmed
                    sync_state.confirmed_nodes.clear();
                    sync_state.is_confirmed = false;
                    // Add ourselves to agreed_nodes (don't clear it)
                    sync_state.agreed_nodes.insert(self.node_id.clone());

                    info!(
                        "💾 [SEQUENCER] [SYNC] Cached request for tx_id={} after agreeing to proposal",
                        transaction_id
                    );

                    true
                } else {
                    drop(pending);
                    // Re-acquire sync_state lock
                    sync_state = self.sync_state.write().await;
                    missing_at_proposal = true;
                    false
                }
            } else {
                // We're processing a different transaction
                false
            };

            if should_agree {
                let node_id_clone = node_id.clone();
                let was_new = sync_state.agreed_nodes.insert(node_id);
                if was_new {
                    info!(
                        "✅ [SEQUENCER] [SYNC] Node {} agreed to process tx_id={} (agreed: {}/{}, threshold: {})",
                        node_id_clone,
                        transaction_id,
                        sync_state.agreed_nodes.len(),
                        sync_state.total_nodes,
                        (sync_state.total_nodes / 2) + 1
                    );
                } else {
                    info!(
                        "🔄 [SEQUENCER] [SYNC] Node {} already agreed to tx_id={}",
                        node_id_clone, transaction_id
                    );
                }
            } else if missing_at_proposal {
                // Request is missing - trigger fetch/wait loop
                drop(sync_state);
                self.trigger_missing_request_fetch(transaction_id.clone(), sequence)
                    .await;
                sync_state = self.sync_state.write().await;
            } else {
                warn!(
                    "⚠️ [SEQUENCER] [SYNC] Node {} proposed tx_id={} but we're processing {:?}",
                    node_id, transaction_id, sync_state.current_processing
                );
            }
        } else if state == "completed" {
            // Track which nodes have confirmed completion
            if sync_state.current_processing.as_ref() == Some(&transaction_id) {
                let node_id_clone = node_id.clone();
                let was_new = sync_state.confirmed_nodes.insert(node_id);
                let confirmed_count = sync_state.confirmed_nodes.len();

                if was_new {
                    info!(
                        "✅ [SEQUENCER] [SYNC] Node {} confirmed completion of tx_id={} (confirmed: {}/{})",
                        node_id_clone, transaction_id, confirmed_count, sync_state.total_nodes
                    );

                    // Check if all nodes have confirmed
                    if confirmed_count >= sync_state.total_nodes {
                        sync_state.is_confirmed = true;
                        // Clear current_processing to allow next transaction to be picked up
                        sync_state.current_processing = None;
                        sync_state.agreed_nodes.clear();
                        sync_state.confirmed_nodes.clear();
                        sync_state.is_confirmed = false; // Reset for next transaction

                        // Clear the cached request
                        drop(sync_state);
                        let mut cache = self.current_request_cache.write().await;
                        *cache = None;
                        drop(cache);

                        // CRITICAL: Increment round and clear selection state for next transaction
                        let mut round_lock = self.vault_sequencer_round.write().await;
                        let old_round = *round_lock;
                        *round_lock += 1;
                        let new_round = *round_lock;
                        drop(round_lock);

                        // Clear locked request
                        let mut locked = self.locked_request.write().await;
                        *locked = None;
                        drop(locked);

                        // Clear final node cache for old round
                        let mut cache = self.final_node_cache.write().await;
                        cache.remove(&old_round);
                        drop(cache);

                        info!(
                            "🎉 [VAULT_SEQUENCER] [SYNC] ALL nodes confirmed completion of tx_id={}! Round incremented: {} -> {}. State cleared, ready for next transaction.",
                            transaction_id, old_round, new_round
                        );
                        info!(
                            "🔓 [VAULT_SEQUENCER] Released queue token and advanced cursor (round {} -> {})",
                            old_round, new_round
                        );
                    }
                } else {
                    info!(
                        "🔄 [SEQUENCER] [SYNC] Node {} already confirmed tx_id={}",
                        node_id_clone, transaction_id
                    );
                }
            } else {
                info!(
                    "ℹ️ [SEQUENCER] [SYNC] Node {} confirmed tx_id={} but we're processing {:?}",
                    node_id, transaction_id, sync_state.current_processing
                );
            }
        }
    }

    /// Spawn a fetch/wait loop for proposals where we don't yet have the request
    async fn trigger_missing_request_fetch(&self, transaction_id: String, sequence: u64) {
        {
            let mut sync_state = self.sync_state.write().await;
            sync_state.missing_requests.insert(transaction_id.clone());
        }

        info!(
            "📡 [SEQUENCER] [SYNC] Proposal received before request, awaiting fetch: tx_id={}, sequence={}",
            transaction_id, sequence
        );

        let sequencer_clone = self.clone();
        tokio::spawn(async move {
            sequencer_clone
                .wait_for_missing_request_and_reagree(transaction_id, sequence)
                .await;
        });
    }

    /// Wait for a missing request to arrive and then agree to the proposal
    async fn wait_for_missing_request_and_reagree(&self, transaction_id: String, sequence: u64) {
        let timeout_ms = 5000; // 5 seconds timeout
        let check_interval_ms = 100; // Check every 100ms

        let start = std::time::Instant::now();

        while start.elapsed().as_millis() < timeout_ms as u128 {
            // Check if request has arrived
            let maybe_request = {
                let pending = self.pending_requests.read().await;
                pending.get(&transaction_id).cloned()
            };

            if let Some(request) = maybe_request {
                // Request arrived! Now we can agree
                let mut sync_state = self.sync_state.write().await;

                // Only proceed if we're still waiting for this request and nothing else is processing
                if sync_state.missing_requests.contains(&transaction_id)
                    && sync_state.current_processing.is_none()
                {
                    // Remove from missing_requests
                    sync_state.missing_requests.remove(&transaction_id);

                    // Remove from pending_requests
                    let mut pending = self.pending_requests.write().await;
                    let request = pending.remove(&transaction_id).unwrap();
                    drop(pending);

                    // Cache the request
                    let mut cache = self.current_request_cache.write().await;
                    *cache = Some(request.clone());
                    drop(cache);

                    // Set as current processing and agree
                    sync_state.current_processing = Some(transaction_id.clone());
                    sync_state.current_sequence = sequence;
                    sync_state.confirmed_nodes.clear();
                    sync_state.is_confirmed = false;
                    sync_state.agreed_nodes.insert(self.node_id.clone());

                    info!(
                        "✅ [SEQUENCER] [SYNC] Missing request {} arrived! Agreed to proposal (agreed: {}/{}, threshold: {})",
                        transaction_id,
                        sync_state.agreed_nodes.len(),
                        sync_state.total_nodes,
                        (sync_state.total_nodes / 2) + 1
                    );

                    // Broadcast our agreement
                    if let Some(message_tx) = &self.message_tx {
                        let broadcast_data =
                            serde_json::to_vec(&crate::types::GossipsubMessage::SequencerSync {
                                transaction_id: transaction_id.clone(),
                                sequence,
                                node_id: self.node_id.clone(),
                                state: "proposed".to_string(),
                            });
                        if let Ok(data) = broadcast_data {
                            let _ = message_tx
                                .send(crate::types::ChannelMessage::Broadcast {
                                    topic: "sequencer-sync".to_string(),
                                    data,
                                })
                                .await;
                        }
                    }

                    return;
                } else {
                    // State changed - we're no longer waiting or something else is processing
                    info!(
                        "ℹ️ [SEQUENCER] [SYNC] Request {} arrived but state changed (current_processing: {:?})",
                        transaction_id, sync_state.current_processing
                    );
                    sync_state.missing_requests.remove(&transaction_id);
                    return;
                }
            }

            // Wait a bit before checking again
            tokio::time::sleep(tokio::time::Duration::from_millis(check_interval_ms)).await;
        }

        // Timeout - request never arrived
        warn!(
            "⏱️ [SEQUENCER] [SYNC] Timeout waiting for request {} (sequence {}), removing from missing_requests",
            transaction_id, sequence
        );
        let mut sync_state = self.sync_state.write().await;
        sync_state.missing_requests.remove(&transaction_id);
    }

    /// Cache the request for the current processing transaction
    /// This is called when we propose a transaction and have the request object
    pub async fn cache_current_request(&self, request: ContractTransactionRequest) {
        let mut cache = self.current_request_cache.write().await;
        *cache = Some(request);
        info!("💾 [SEQUENCER] Cached request for current processing transaction");
    }

    /// Propose a transaction for processing and wait for consensus
    pub async fn propose_transaction(&self, transaction_id: &str, sequence: u64) -> Result<bool> {
        let mut sync_state = self.sync_state.write().await;

        // Check if we can propose (nothing currently processing or previous is confirmed)
        if let Some(current_tx) = &sync_state.current_processing {
            if !sync_state.is_confirmed {
                warn!(
                    "⏸️ [SEQUENCER] [PROPOSE] Cannot propose tx_id={} (sequence={}): waiting for {} to be confirmed",
                    transaction_id, sequence, current_tx
                );
                return Ok(false);
            }
            // Previous is confirmed, we can proceed
            info!(
                "✅ [SEQUENCER] [PROPOSE] Previous transaction {} confirmed, proceeding with tx_id={}",
                current_tx, transaction_id
            );
        }

        // Set as current processing
        sync_state.current_processing = Some(transaction_id.to_string());
        sync_state.current_sequence = sequence;
        sync_state.agreed_nodes.clear();
        sync_state.confirmed_nodes.clear();
        sync_state.is_confirmed = false;
        sync_state.agreed_nodes.insert(self.node_id.clone());

        let current_sequence = sync_state.current_sequence;
        drop(sync_state);

        // Broadcast proposal
        if let Some(message_tx) = &self.message_tx {
            let broadcast_data =
                serde_json::to_vec(&crate::types::GossipsubMessage::SequencerSync {
                    transaction_id: transaction_id.to_string(),
                    sequence: current_sequence,
                    node_id: self.node_id.clone(),
                    state: "proposed".to_string(),
                })?;

            message_tx
                .send(crate::types::ChannelMessage::Broadcast {
                    topic: "sequencer-sync".to_string(),
                    data: broadcast_data,
                })
                .await?;

            info!(
                "📤 [SEQUENCER] [PROPOSE] Proposed transaction tx_id={} for processing (sequence={})",
                transaction_id, current_sequence
            );
        }

        Ok(true)
    }

    /// Check if we have consensus to process the current transaction
    pub async fn has_consensus(&self) -> bool {
        let sync_state = self.sync_state.read().await;

        if sync_state.current_processing.is_none() {
            info!("❌ [SEQUENCER] [CONSENSUS] No transaction currently proposed");
            return false;
        }

        // Need majority consensus (at least 50% + 1 nodes)
        let threshold = (sync_state.total_nodes / 2) + 1;
        let agreed_count = sync_state.agreed_nodes.len();
        let has_consensus = agreed_count >= threshold;

        if has_consensus {
            info!(
                "✅ [SEQUENCER] [CONSENSUS] Consensus reached for tx_id={}: {}/{} nodes agreed (threshold: {})",
                sync_state.current_processing.as_ref().unwrap(),
                agreed_count,
                sync_state.total_nodes,
                threshold
            );
        } else {
            // Log every time we check (not just once) so we can see progress
            // Use a timestamp to ensure we can see if it's being called multiple times
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            info!(
                "⏳ [SEQUENCER] [CONSENSUS] [{}] Waiting for consensus: {}/{} nodes agreed (need {}), agreed_nodes: {:?}",
                timestamp, agreed_count, sync_state.total_nodes, threshold,
                sync_state.agreed_nodes.iter().collect::<Vec<_>>()
            );
        }

        has_consensus
    }

    /// Mark transaction as processing and broadcast
    pub async fn mark_processing(&self, transaction_id: &str) -> Result<()> {
        if let Some(message_tx) = &self.message_tx {
            let sync_state = self.sync_state.read().await;
            let sequence = sync_state.current_sequence;
            drop(sync_state);

            if sequence == 1 {
                info!(
                    "🧭 [VAULT_SEQUENCER] Processing first transaction in queue: tx_id={}",
                    transaction_id
                );
            }

            let broadcast_data =
                serde_json::to_vec(&crate::types::GossipsubMessage::SequencerSync {
                    transaction_id: transaction_id.to_string(),
                    sequence,
                    node_id: self.node_id.clone(),
                    state: "processing".to_string(),
                })?;

            message_tx
                .send(crate::types::ChannelMessage::Broadcast {
                    topic: "sequencer-sync".to_string(),
                    data: broadcast_data,
                })
                .await?;

            info!(
                "🚀 [SEQUENCER] [PROCESSING] Marked tx_id={} as processing (sequence={})",
                transaction_id, sequence
            );
        }
        Ok(())
    }

    /// Mark transaction as completed and broadcast confirmation
    /// NOTE: State is NOT cleared here - it's cleared when ALL nodes confirm
    pub async fn mark_completed(&self, transaction_id: &str) -> Result<()> {
        let mut sync_state = self.sync_state.write().await;

        if sync_state.current_processing.as_deref() == Some(transaction_id) {
            let sequence = sync_state.current_sequence;

            // Add ourselves to confirmed nodes
            sync_state.confirmed_nodes.insert(self.node_id.clone());
            let confirmed_count = sync_state.confirmed_nodes.len();

            info!(
                "✅ [SEQUENCER] [COMPLETE] Marked tx_id={} as completed locally (sequence={}, confirmed: {}/{})",
                transaction_id, sequence, confirmed_count, sync_state.total_nodes
            );

            drop(sync_state);

            // Broadcast completion confirmation
            if let Some(message_tx) = &self.message_tx {
                let broadcast_data =
                    serde_json::to_vec(&crate::types::GossipsubMessage::SequencerSync {
                        transaction_id: transaction_id.to_string(),
                        sequence,
                        node_id: self.node_id.clone(),
                        state: "completed".to_string(),
                    })?;

                message_tx
                    .send(crate::types::ChannelMessage::Broadcast {
                        topic: "sequencer-sync".to_string(),
                        data: broadcast_data,
                    })
                    .await?;

                info!(
                    "📤 [SEQUENCER] [COMPLETE] Broadcasted completion confirmation for tx_id={}",
                    transaction_id
                );
            }

            // Check if we should clear state (all nodes confirmed)
            let mut sync_state = self.sync_state.write().await;
            if sync_state.confirmed_nodes.len() >= sync_state.total_nodes {
                let completed_tx = sync_state.current_processing.clone();
                sync_state.current_processing = None;
                sync_state.agreed_nodes.clear();
                sync_state.confirmed_nodes.clear();
                sync_state.is_confirmed = false;

                // Clear the cached request
                drop(sync_state);
                let mut cache = self.current_request_cache.write().await;
                *cache = None;

                info!(
                    "🎉 [SEQUENCER] [COMPLETE] ALL nodes confirmed tx_id={}! State cleared, ready for next transaction.",
                    completed_tx.as_ref().unwrap()
                );
                if let Some(completed) = completed_tx {
                    info!(
                        "🔓 [SEQUENCER] Released queue token for tx_id={}, allowing dequeue of next request",
                        completed
                    );
                }
            } else {
                info!(
                    "⏳ [SEQUENCER] [COMPLETE] Waiting for more confirmations: {}/{} nodes confirmed tx_id={}",
                    sync_state.confirmed_nodes.len(),
                    sync_state.total_nodes,
                    transaction_id
                );
            }
        } else {
            warn!(
                "⚠️ [SEQUENCER] [COMPLETE] Tried to mark tx_id={} as completed but current_processing={:?}",
                transaction_id, sync_state.current_processing
            );
        }

        Ok(())
    }

    /// Update total nodes count (for consensus threshold)
    pub async fn update_total_nodes(&self, total_nodes: usize) {
        let mut sync_state = self.sync_state.write().await;
        let old_total = sync_state.total_nodes;
        sync_state.total_nodes = total_nodes;
        info!(
            "🔄 [SEQUENCER] [CONFIG] Updated total nodes: {} -> {} (consensus threshold: {})",
            old_total,
            total_nodes,
            (total_nodes / 2) + 1
        );
    }
}

// ============================================================================
// Network Transaction Sequencer
// ============================================================================
// This sequencer handles transactions that use the network DKG group key
// (e.g., NetworkToTarget, and potentially other network-level transactions)
// to prevent nonce collisions when multiple transactions are processed in parallel.

/// Enum to distinguish between different network transaction flows
#[derive(Clone, Debug)]
pub enum NetworkTransactionFlow {
    /// Network withdrawal transaction (NetworkToTarget)
    NetworkToTarget {
        intent: DepositIntent,
        intent_hash: String,
        transaction_type: TransactionType,
        amount: u128,
        tx_bytes: Vec<u8>,
        eth_tx: crate::chain_abstraction::EthereumTransaction,
        user_tweaked_share: Option<k256::Scalar>,
        user_eth_address: Option<String>,
    },
    /// Withdraw liquidity transaction (solver payout)
    WithdrawLiquidity {
        solver_address: String,
        eth_address: String,
        amount: u128,
        tx_bytes: Vec<u8>,
        eth_tx: crate::chain_abstraction::EthereumTransaction,
    },
    /// Reward payout transaction (solver reward)
    RewardPayout {
        solver_address: String,
        eth_address: String,
        amount: u128,
        tx_bytes: Vec<u8>,
        eth_tx: crate::chain_abstraction::EthereumTransaction,
    },
}

/// Request to execute a network transaction
#[derive(Clone, Debug)]
pub struct NetworkTransactionRequest {
    /// The type of transaction flow
    pub flow: NetworkTransactionFlow,
    /// Transaction ID (unique identifier for this transaction)
    pub transaction_id: String,
    /// Sequence number for deterministic ordering (set when request is received)
    pub sequence: u64,
}

/// Sequencer synchronization state for network transactions
#[derive(Clone, Debug)]
struct NetworkTransactionSyncState {
    /// Transaction ID currently being processed
    current_processing: Option<String>,
    /// Sequence number for the current processing transaction
    current_sequence: u64,
    /// Global sequence counter for deterministic ordering
    global_sequence: u64,
    /// Nodes that have agreed to process the current request
    agreed_nodes: HashSet<String>,
    /// Nodes that have confirmed completion of the current request
    confirmed_nodes: HashSet<String>,
    /// Total number of active nodes (for consensus threshold)
    total_nodes: usize,
    /// Whether current transaction is confirmed (all nodes confirmed)
    is_confirmed: bool,
}

/// Sequencer for network transactions (Main ETH Address)
///
/// Production-ready implementation with deterministic final node selection.
/// Only the selected final node picks which request to process next.
/// Other nodes wait for the SELECT message from the final node.
///
/// CRITICAL: Final node selection is deterministic based on:
/// 1. Round number (increments after each transaction)
/// 2. Previous block hash (shared across network)
/// 3. Domain tag "MAIN" for separation from vault sequencer
///
/// Flow:
/// 1. All nodes receive transaction requests (via gossip)
/// 2. Final node is selected: idx = H("MAIN" || prev_block_hash || round) mod |Nodes|
/// 3. Only final node selects next request and broadcasts SELECT message
/// 4. Other nodes verify SELECT, send ACK if they have it, or MISSING if not
/// 5. All nodes process the selected request
/// 6. Round advances for next selection
#[derive(Clone)]
pub struct NetworkTransactionSequencer {
    /// Pending requests sorted by transaction_id (BTreeMap maintains sorted order)
    pending_requests: Arc<RwLock<BTreeMap<String, NetworkTransactionRequest>>>,
    /// Synchronization state
    sync_state: Arc<RwLock<NetworkTransactionSyncState>>,
    /// Message channel for broadcasting sequencer sync messages
    message_tx: Option<mpsc::Sender<crate::types::ChannelMessage>>,
    /// Local node ID
    node_id: String,
    /// Cached request for the current processing transaction (set when we propose it)
    current_request_cache: Arc<RwLock<Option<NetworkTransactionRequest>>>,

    // VRF + Consensus for final node selection (Main Sequencer)
    /// Local peer ID for final node selection
    local_peer_id: Option<libp2p::PeerId>,
    /// Main sequencer round number (independent from signing and vault rounds)
    main_sequencer_round: Arc<RwLock<u64>>,
    /// VRF service for node selection (separate instance with "main_seq:" prefix)
    vrf_service: Option<Arc<crate::protocols::VrfService>>,
    /// Consensus node for determining final node
    consensus_node: Option<Arc<RwLock<crate::consensus::ConsensusNode>>>,
    /// Available nodes for final node selection
    available_nodes: Arc<RwLock<Vec<libp2p::PeerId>>>,
    /// Cache of selected final nodes per round (populated by consensus)
    final_node_cache: Arc<RwLock<HashMap<u64, libp2p::PeerId>>>,
    /// Locked request ID selected by final node (per round)
    locked_request: Arc<RwLock<Option<String>>>,
}

impl NetworkTransactionSequencer {
    /// Create a new network transaction sequencer
    /// Uses VRF + Consensus for final node selection
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(RwLock::new(BTreeMap::new())),
            sync_state: Arc::new(RwLock::new(NetworkTransactionSyncState {
                current_processing: None,
                current_sequence: 0,
                global_sequence: 0,
                agreed_nodes: HashSet::new(),
                confirmed_nodes: HashSet::new(),
                total_nodes: 0,
                is_confirmed: false,
            })),
            message_tx: None,
            node_id: String::new(),
            current_request_cache: Arc::new(RwLock::new(None)),

            // Initialize VRF + Consensus fields
            local_peer_id: None,
            main_sequencer_round: Arc::new(RwLock::new(0)),
            vrf_service: None,
            consensus_node: None,
            available_nodes: Arc::new(RwLock::new(Vec::new())),
            final_node_cache: Arc::new(RwLock::new(HashMap::new())),
            locked_request: Arc::new(RwLock::new(None)),
        }
    }

    /// Set local peer ID for final node selection
    pub fn set_local_peer_id(&mut self, peer_id: libp2p::PeerId) {
        self.local_peer_id = Some(peer_id);
    }

    /// Update available nodes for final node selection
    pub async fn update_available_nodes(&self, nodes: Vec<libp2p::PeerId>) {
        let mut available = self.available_nodes.write().await;
        *available = nodes;
        info!(
            "🔄 [MAIN_SEQUENCER] Updated available nodes: count={}",
            available.len()
        );
    }

    /// Select final node deterministically for current round using VRF + Consensus
    /// Returns the peer ID of the selected node (from consensus cache)
    async fn select_final_node(&self) -> Result<libp2p::PeerId> {
        let round = *self.main_sequencer_round.read().await;

        // Check if consensus has completed for this round
        let cache = self.final_node_cache.read().await;
        if let Some(final_node) = cache.get(&round) {
            return Ok(*final_node);
        }

        // Consensus not complete yet
        Err(anyhow::anyhow!(
            "Consensus not complete for main sequencer round {}. Run VRF selection and consensus first.",
            round
        ))
    }

    /// Perform VRF node selection for current round
    pub async fn perform_vrf_selection(&self, threshold: usize) -> Result<()> {
        info!("🚦 [MAIN_SEQUENCER] Starting VRF round sync before selection");
        let round = self.sync_round_with_peers().await?;
        info!(
            "🔁 [MAIN_SEQUENCER] VRF round sync completed, proceeding with selection: round={}",
            round
        );
        let nodes = self.available_nodes.read().await.clone();

        if nodes.is_empty() {
            return Err(anyhow::anyhow!("No available nodes for VRF selection"));
        }

        info!(
            "🎯 [MAIN_SEQUENCER] Starting VRF selection for round {} with {} nodes",
            round,
            nodes.len()
        );

        if let Some(vrf_service) = &self.vrf_service {
            // Perform VRF selection
            let selection_result = vrf_service
                .perform_node_selection_without_broadcast(
                    &nodes,
                    threshold,
                    round,
                    "main_sequencer",
                )
                .await?;

            info!(
                "✅ [MAIN_SEQUENCER] VRF selection completed for round {}: {} nodes selected",
                round,
                selection_result.selected_nodes.len()
            );

            // Create broadcast with main sequencer specific message type
            if let Some(broadcast_msg) = vrf_service.create_broadcast_for_round(round).await {
                if let Some(message_tx) = &self.message_tx {
                    let broadcast_data = serde_json::to_vec(
                        &crate::types::GossipsubMessage::MainSequencerVrfSelectedNodes(
                            broadcast_msg,
                        ),
                    )?;

                    message_tx
                        .send(crate::types::ChannelMessage::Broadcast {
                            topic: "main-sequencer-vrf".to_string(),
                            data: broadcast_data,
                        })
                        .await?;

                    info!(
                        "📤 [MAIN_SEQUENCER] Broadcasted VRF selection for round {}",
                        round
                    );
                }
            }
        } else {
            return Err(anyhow::anyhow!("VRF service not available"));
        }

        Ok(())
    }

    pub async fn sync_round_with_peers(&self) -> Result<u64> {
        if let Some(vrf_service) = &self.vrf_service {
            let round = *self.main_sequencer_round.read().await;
            vrf_service.set_current_round(round).await;
            let synced_round = vrf_service
                .sync_rounds(VrfRoundSyncKind::MainSequencer)
                .await?;

            let mut local_round = self.main_sequencer_round.write().await;
            *local_round = synced_round;
            Ok(synced_round)
        } else {
            Ok(*self.main_sequencer_round.read().await)
        }
    }

    /// Check if we have enough VRF selections to start consensus
    pub async fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        if let Some(vrf_service) = &self.vrf_service {
            vrf_service.can_start_consensus(round, min_selections).await
        } else {
            false
        }
    }

    /// Access underlying VRF service (read-only) for main network sequencer
    pub fn vrf_service(&self) -> Option<&crate::protocols::VrfService> {
        self.vrf_service.as_deref()
    }

    /// Start consensus to determine final node for current round
    pub async fn start_consensus(&self, round: u64) -> Result<crate::types::ConsensusResult> {
        info!("🎯 [MAIN_SEQUENCER] Starting consensus for round {}", round);

        // Get VRF-selected nodes from VRF service
        let selected_nodes = if let Some(vrf_service) = &self.vrf_service {
            vrf_service
                .get_all_selected_nodes_with_frequencies(round)
                .await
        } else {
            return Err(anyhow::anyhow!("VRF service not available"));
        };

        if selected_nodes.is_empty() {
            return Err(anyhow::anyhow!(
                "No VRF selections available for main sequencer round {}",
                round
            ));
        }

        info!(
            "📊 [MAIN_SEQUENCER] Got {} VRF selections for round {}",
            selected_nodes.len(),
            round
        );

        // Run consensus algorithm
        if let Some(consensus) = &self.consensus_node {
            let mut consensus_node = consensus.write().await;
            consensus_node.add_selected_nodes(round, selected_nodes);

            let result = consensus_node.start_consensus(round)?;

            info!(
                "✅ [MAIN_SEQUENCER] Consensus completed for round {}: final node = {:?}",
                round, result.final_node
            );

            // Cache final node for this round
            let mut cache = self.final_node_cache.write().await;
            cache.insert(round, result.final_node.0);

            Ok(result)
        } else {
            Err(anyhow::anyhow!("Consensus node not available"))
        }
    }

    /// Check if current node is the final node for this round
    pub async fn am_i_final_node(&self) -> Result<bool> {
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        let final_node = self.select_final_node().await?;
        Ok(local_peer == final_node)
    }

    /// Advance to next round
    pub async fn advance_round(&self) {
        let mut round = self.main_sequencer_round.write().await;
        *round += 1;

        // Clear locked request
        let mut locked = self.locked_request.write().await;
        *locked = None;

        info!("📈 [MAIN_SEQUENCER] Advanced to round {}", *round);
    }

    /// Get current round
    pub async fn get_current_round(&self) -> u64 {
        *self.main_sequencer_round.read().await
    }

    /// Set VRF service for main sequencer
    pub fn set_vrf_service(&mut self, vrf_service: Arc<crate::protocols::VrfService>) {
        self.vrf_service = Some(vrf_service);
        info!("🔧 [MAIN_SEQUENCER] VRF service configured");
    }

    pub fn vrf_storage(&self) -> Option<VrfStorage> {
        self.vrf_service
            .as_ref()
            .and_then(|service| service.storage())
    }

    /// Set consensus node for main sequencer
    pub fn set_consensus_node(&mut self, consensus: Arc<RwLock<crate::consensus::ConsensusNode>>) {
        self.consensus_node = Some(consensus);
        info!("🔧 [MAIN_SEQUENCER] Consensus node configured");
    }

    /// Handle VRF selected nodes broadcast from another node
    pub async fn handle_vrf_broadcast(
        &self,
        broadcast: crate::protocols::VrfSelectedNodesBroadcast,
        total_nodes: usize,
    ) -> Result<()> {
        if let Some(vrf_service) = &self.vrf_service {
            vrf_service
                .handle_vrf_broadcast(broadcast, total_nodes)
                .await;
            info!("✅ [MAIN_SEQUENCER] Handled VRF broadcast");
        } else {
            warn!("⚠️ [MAIN_SEQUENCER] VRF service not available for handling broadcast");
        }
        Ok(())
    }

    /// Check and trigger consensus if enough VRF selections received
    pub async fn check_and_trigger_consensus(
        &self,
        round: u64,
        min_selections: usize,
    ) -> Result<Option<crate::types::ConsensusResult>> {
        if self.can_start_consensus(round, min_selections).await {
            info!(
                "🎯 [MAIN_SEQUENCER] Enough VRF selections for round {}, starting consensus",
                round
            );

            match self.start_consensus(round).await {
                Ok(result) => {
                    info!(
                        "✅ [MAIN_SEQUENCER] Consensus complete for round {}: final node = {:?}",
                        round, result.final_node
                    );
                    Ok(Some(result))
                }
                Err(e) => {
                    error!(
                        "❌ [MAIN_SEQUENCER] Failed to start consensus for round {}: {}",
                        round, e
                    );
                    Err(e)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Generate a unique transaction ID for NetworkToTarget transactions
    /// Uses intent_hash directly as it's already unique
    pub fn generate_transaction_id_for_network_to_target(intent_hash: &str) -> String {
        format!("network_to_target:{}", intent_hash)
    }

    /// Generate a unique transaction ID for WithdrawLiquidity transactions
    /// Uses Keccak256 hash of tx_bytes directly to ensure uniqueness
    pub fn generate_transaction_id_for_withdraw_liquidity(tx_bytes: &[u8]) -> String {
        // Hash tx_bytes using Keccak256 (same as Ethereum) to ensure uniqueness
        let hash = Keccak256::digest(tx_bytes);
        format!("withdraw_liquidity:0x{}", hex::encode(hash))
    }

    /// Generate a unique transaction ID for RewardPayout transactions
    /// Uses Keccak256 hash of tx_bytes directly to ensure uniqueness
    pub fn generate_transaction_id_for_reward_payout(tx_bytes: &[u8]) -> String {
        // Hash tx_bytes using Keccak256 (same as Ethereum) to ensure uniqueness
        let hash = Keccak256::digest(tx_bytes);
        format!("reward_payout:0x{}", hex::encode(hash))
    }

    /// Initialize the sequencer with message channel and node ID
    pub async fn initialize(
        &mut self,
        message_tx: mpsc::Sender<crate::types::ChannelMessage>,
        node_id: String,
        total_nodes: usize,
    ) {
        self.message_tx = Some(message_tx);
        self.node_id = node_id.clone();
        let mut sync_state = self.sync_state.write().await;
        sync_state.total_nodes = total_nodes;
        info!(
            "✅ [NETWORK_SEQUENCER] Initialized node {} with {} total nodes",
            node_id, total_nodes
        );
    }

    /// Submit a network transaction request to the sequencer
    pub async fn submit(&self, mut request: NetworkTransactionRequest) -> Result<()> {
        let transaction_id = request.transaction_id.clone();

        // CRITICAL: Hold both locks together to ensure atomic sequence assignment and queue insertion
        let (_sequence, _queue_size) = {
            let mut sync_state = self.sync_state.write().await;
            let mut pending = self.pending_requests.write().await;

            // Assign sequence number (atomic operation)
            sync_state.global_sequence += 1;
            request.sequence = sync_state.global_sequence;
            let sequence = sync_state.global_sequence;

            // Ensure transaction_id uniqueness: if a duplicate exists, append sequence number
            let final_transaction_id = if pending.contains_key(&transaction_id) {
                let unique_id = format!("{}:seq{}", transaction_id, sequence);
                warn!(
                    "⚠️ [NETWORK_SEQUENCER] Duplicate transaction_id detected: {}. Using unique ID: {}",
                    transaction_id, unique_id
                );
                unique_id
            } else {
                transaction_id.clone()
            };

            // Update the request's transaction_id to the final (potentially unique) ID
            request.transaction_id = final_transaction_id.clone();

            // Add to pending requests (BTreeMap maintains sorted order by transaction_id)
            let final_tx_id_for_log = final_transaction_id.clone();
            pending.insert(final_transaction_id, request);
            let queue_size = pending.len();

            info!(
                "📥 [NETWORK_SEQUENCER] Queued transaction: tx_id={}, sequence={}, queue_size={}",
                final_tx_id_for_log, sequence, queue_size
            );

            (sequence, queue_size)
        };

        Ok(())
    }

    /// Get the current processing transaction info (if any)
    pub async fn get_current_processing(&self) -> Option<(String, u64, bool)> {
        let sync_state = self.sync_state.read().await;
        if let Some(tx_id) = &sync_state.current_processing {
            Some((
                tx_id.clone(),
                sync_state.current_sequence,
                sync_state.is_confirmed,
            ))
        } else {
            None
        }
    }

    /// Get the request for the current processing transaction
    pub async fn get_current_request(&self) -> Option<NetworkTransactionRequest> {
        // First, check if we have it cached (we proposed it)
        {
            let cache = self.current_request_cache.read().await;
            if let Some(request) = cache.as_ref().cloned() {
                info!(
                    "🎯 [NETWORK_SEQUENCER] Retrieved current request from cache: tx_id={}, sequence={}",
                    request.transaction_id, request.sequence
                );
                return Some(request);
            }
        }

        // If not in cache, try to get it from the queue (we received a "proposed" message)
        let sync_state = self.sync_state.read().await;
        let current_tx = sync_state.current_processing.clone();
        drop(sync_state);

        if let Some(tx_id) = current_tx {
            let mut pending = self.pending_requests.write().await;
            if let Some(request) = pending.remove(&tx_id) {
                info!(
                    "🎯 [NETWORK_SEQUENCER] Retrieved current request from queue: tx_id={}, sequence={}",
                    request.transaction_id, request.sequence
                );
                Some(request)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Check if the local node has confirmed the current processing transaction
    pub async fn is_locally_confirmed(&self) -> bool {
        let sync_state = self.sync_state.read().await;
        sync_state.confirmed_nodes.contains(&self.node_id)
    }

    /// Get the next request to process based on final node selection
    /// Only the final node selects the request, others wait for SELECT message
    pub async fn get_next_request(&self) -> Option<NetworkTransactionRequest> {
        let sync_state = self.sync_state.read().await;

        // CRITICAL: Don't move to next until previous is confirmed by all nodes
        if let Some(current_tx) = &sync_state.current_processing {
            if !sync_state.is_confirmed {
                info!(
                    "⏳ [MAIN_SEQUENCER] Waiting for confirmation: current_tx={}, confirmed_nodes={}/{}, is_confirmed={}",
                    current_tx,
                    sync_state.confirmed_nodes.len(),
                    sync_state.total_nodes,
                    sync_state.is_confirmed
                );
                return None;
            }
            info!(
                "✅ [MAIN_SEQUENCER] Previous transaction {} confirmed, ready for next",
                current_tx
            );
        }

        drop(sync_state);

        // Small delay to allow VRF round sync and broadcasts to propagate
        // before selecting the next request. This helps keep sequencer rounds
        // aligned across nodes in parallel transaction scenarios.
        tokio::time::sleep(tokio::time::Duration::from_millis(3000)).await;

        // Check if there's a locked request (selected by final node)
        {
            let locked = self.locked_request.read().await;
            if let Some(request_id) = &*locked {
                // We have a locked request from final node - retrieve and return it
                let mut pending = self.pending_requests.write().await;
                if let Some(request) = pending.remove(request_id) {
                    info!(
                        "🔓 [MAIN_SEQUENCER] Processing locked request from final node: {}",
                        request_id
                    );
                    return Some(request);
                }
            }
        }

        // Check if we have pending requests
        let queue_len = {
            let pending = self.pending_requests.read().await;
            pending.len()
        };

        if queue_len == 0 {
            return None;
        }

        info!(
            "📤 [MAIN_SEQUENCER] Dequeue next transaction attempt: queue_len={}, round={}",
            queue_len,
            *self.main_sequencer_round.read().await
        );

        // Get current round and check if consensus is complete
        let round = *self.main_sequencer_round.read().await;
        let cache = self.final_node_cache.read().await;
        let has_final_node = cache.contains_key(&round);
        drop(cache);

        if !has_final_node {
            // Consensus not complete - trigger VRF if not already done
            // This matches signing module pattern: perform VRF when starting to process
            info!(
                "🎯 [MAIN_SEQUENCER] No final node for round {}, triggering VRF selection",
                round
            );

            // Get available nodes
            let nodes = self.available_nodes.read().await.clone();
            if nodes.is_empty() {
                warn!("⚠️ [MAIN_SEQUENCER] No available nodes for VRF selection");
                return None;
            }

            info!(
                "🔍 [MAIN_SEQUENCER] Available nodes for VRF: count={}, nodes={:?}",
                nodes.len(),
                nodes.iter().map(|p| p.to_string()).collect::<Vec<_>>()
            );

            // Check if VRF service is available
            if self.vrf_service.is_none() {
                error!("❌ [MAIN_SEQUENCER] VRF service not configured! Cannot perform selection.");
                return None;
            }

            // Trigger VRF selection (matches signing module: spawn async to avoid blocking)
            let threshold = nodes.len(); // All nodes must participate
            let sequencer_clone = self.clone();
            tokio::spawn(async move {
                info!(
                    "🚀 [MAIN_SEQUENCER] Starting VRF selection task for round {}",
                    round
                );
                if let Err(e) = sequencer_clone.perform_vrf_selection(threshold).await {
                    error!("❌ [MAIN_SEQUENCER] VRF selection failed: {}", e);
                } else {
                    info!(
                        "✅ [MAIN_SEQUENCER] VRF selection task completed for round {}",
                        round
                    );
                }
            });

            // Return None - consensus will complete after VRF broadcasts are collected
            return None;
        }

        // Consensus complete - check if we are the final node
        match self.am_i_final_node().await {
            Ok(true) => {
                // We are the final node - select the request
                let mut pending = self.pending_requests.write().await;
                if let Some((tx_id, request)) = pending.pop_first() {
                    let sequence = request.sequence;
                    let queue_size = pending.len();
                    info!(
                        "🎯 [MAIN_SEQUENCER] Final node selecting request: tx_id={}, sequence={}, remaining={}",
                        tx_id, sequence, queue_size
                    );

                    // Lock this request
                    drop(pending);
                    let mut locked = self.locked_request.write().await;
                    *locked = Some(tx_id.clone());

                    // Broadcast SELECT message
                    if let Err(e) = self.broadcast_select_message(&tx_id, &request).await {
                        warn!("⚠️ [MAIN_SEQUENCER] Failed to broadcast SELECT: {}", e);
                    }

                    drop(locked);
                    Some(request)
                } else {
                    None
                }
            }
            Ok(false) => {
                // We are NOT the final node - wait for SELECT message
                None
            }
            Err(e) => {
                warn!(
                    "⚠️ [MAIN_SEQUENCER] Error checking final node status: {}",
                    e
                );
                None
            }
        }
    }

    /// Broadcast SELECT message (called by final node only)
    async fn broadcast_select_message(
        &self,
        request_id: &str,
        request: &NetworkTransactionRequest,
    ) -> Result<()> {
        let round = *self.main_sequencer_round.read().await;
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        // Helpful context for debugging which network flow is being selected
        let flow_label = match &request.flow {
            NetworkTransactionFlow::NetworkToTarget {
                intent_hash,
                transaction_type,
                amount,
                ..
            } => {
                format!(
                    "NetworkToTarget(intent_hash={}, type={:?}, amount={})",
                    intent_hash, transaction_type, amount
                )
            }
            NetworkTransactionFlow::WithdrawLiquidity {
                solver_address,
                eth_address,
                amount,
                ..
            } => {
                format!(
                    "WithdrawLiquidity(solver={}, eth_address={}, amount={})",
                    solver_address, eth_address, amount
                )
            }
            NetworkTransactionFlow::RewardPayout {
                solver_address,
                eth_address,
                amount,
                ..
            } => {
                format!(
                    "RewardPayout(solver={}, eth_address={}, amount={})",
                    solver_address, eth_address, amount
                )
            }
        };

        info!(
            "📤 [MAIN_SEQUENCER] Broadcasting SELECT: round={}, request_id={}, flow={}",
            round, request_id, flow_label
        );

        // Create signature (simplified - in production use proper signing)
        let signature = vec![]; // TODO: Sign with node's private key

        // Broadcast via message channel
        if let Some(tx) = &self.message_tx {
            let msg = crate::types::ChannelMessage::Broadcast {
                topic: "main-sequencer-select".to_string(),
                data: serde_json::to_vec(&crate::types::GossipsubMessage::MainSequencerSelect {
                    round,
                    request_id: request_id.to_string(),
                    final_node_id: local_peer,
                    signature,
                })?,
            };

            tx.send(msg)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send SELECT: {}", e))?;
        }

        Ok(())
    }

    /// Broadcast ACK message
    async fn broadcast_ack(&self, request_id: &str) -> Result<()> {
        let round = *self.main_sequencer_round.read().await;
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        if let Some(tx) = &self.message_tx {
            let msg = crate::types::ChannelMessage::Broadcast {
                topic: "main-sequencer-ack".to_string(),
                data: serde_json::to_vec(&crate::types::GossipsubMessage::MainSequencerAck {
                    round,
                    request_id: request_id.to_string(),
                    node_id: local_peer,
                })?,
            };

            tx.send(msg)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send ACK: {}", e))?;
        }

        Ok(())
    }

    /// Broadcast MISSING message
    async fn broadcast_missing(&self, request_id: &str) -> Result<()> {
        let round = *self.main_sequencer_round.read().await;
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        if let Some(tx) = &self.message_tx {
            let msg = crate::types::ChannelMessage::Broadcast {
                topic: "main-sequencer-missing".to_string(),
                data: serde_json::to_vec(&crate::types::GossipsubMessage::MainSequencerMissing {
                    round,
                    request_id: request_id.to_string(),
                    node_id: local_peer,
                })?,
            };

            tx.send(msg)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send MISSING: {}", e))?;
        }

        Ok(())
    }

    /// Handle SELECT message from final node
    pub async fn handle_select_message(
        &self,
        round: u64,
        request_id: String,
        final_node_id: libp2p::PeerId,
    ) -> Result<()> {
        let current_round = *self.main_sequencer_round.read().await;

        if round != current_round {
            warn!(
                "⚠️ [MAIN_SEQUENCER] SELECT message for wrong round: expected={}, got={}",
                current_round, round
            );
            return Ok(());
        }

        // Verify the sender is actually the final node
        let expected_final = self.select_final_node().await?;
        if final_node_id != expected_final {
            warn!(
                "⚠️ [MAIN_SEQUENCER] SELECT from non-final node: expected={:?}, got={:?}",
                expected_final, final_node_id
            );
            return Ok(());
        }

        // Lock this request
        let mut locked = self.locked_request.write().await;
        *locked = Some(request_id.clone());

        info!(
            "🔒 [MAIN_SEQUENCER] Locked request from final node: round={}, request_id={}",
            round, request_id
        );

        // Check if we have this request
        let pending = self.pending_requests.read().await;
        let has_request = pending.contains_key(&request_id);
        drop(pending);

        if has_request {
            info!(
                "✅ [MAIN_SEQUENCER] Have request, sending ACK: {}",
                request_id
            );
            self.broadcast_ack(&request_id).await?;
        } else {
            warn!(
                "⚠️ [MAIN_SEQUENCER] Missing request, sending MISSING: {}",
                request_id
            );
            self.broadcast_missing(&request_id).await?;

            // Wait for request to arrive
            info!(
                "⏳ [MAIN_SEQUENCER] Waiting for missing request: {}",
                request_id
            );
            self.wait_for_request(&request_id, round).await?;
        }

        Ok(())
    }

    /// Handle ACK for a SELECT message to track agreement progress
    pub async fn handle_select_ack(&self, round: u64, request_id: &str, node_id: libp2p::PeerId) {
        let current_round = *self.main_sequencer_round.read().await;

        if round != current_round {
            warn!(
                "⚠️ [MAIN_SEQUENCER] ACK for wrong round: expected={}, got={}",
                current_round, round
            );
            return;
        }

        let mut sync_state = self.sync_state.write().await;

        // Only track ACKs for the currently processing or locked request
        let is_for_current = sync_state
            .current_processing
            .as_ref()
            .map(|tx| tx == request_id)
            .unwrap_or(false);

        let is_locked = {
            let locked = self.locked_request.read().await;
            locked.as_deref() == Some(request_id)
        };

        if !is_for_current && !is_locked {
            info!(
                "ℹ️ [MAIN_SEQUENCER] Ignoring ACK for unrelated request: {} (current={:?}, locked={})",
                request_id,
                sync_state.current_processing,
                is_locked
            );
            return;
        }

        let node_id_str = node_id.to_string();
        if sync_state.agreed_nodes.insert(node_id_str.clone()) {
            info!(
                "✅ [MAIN_SEQUENCER] ACK recorded: request_id={}, from={}, agreed: {}/{} (threshold: {})",
                request_id,
                node_id_str,
                sync_state.agreed_nodes.len(),
                sync_state.total_nodes,
                (sync_state.total_nodes / 2) + 1
            );
        } else {
            info!(
                "🔄 [MAIN_SEQUENCER] Duplicate ACK ignored for request_id={} from {}",
                request_id, node_id_str
            );
        }
    }

    /// Wait for a missing request to arrive (with timeout)
    async fn wait_for_request(&self, request_id: &str, round: u64) -> Result<()> {
        let timeout_ms = 5000; // 5 seconds timeout
        let check_interval_ms = 100; // Check every 100ms

        let start = std::time::Instant::now();

        while start.elapsed().as_millis() < timeout_ms as u128 {
            // Check if request has arrived
            let pending = self.pending_requests.read().await;
            if pending.contains_key(request_id) {
                drop(pending);

                info!(
                    "✅ [MAIN_SEQUENCER] Missing request {} arrived!",
                    request_id
                );

                // Send ACK now that we have it
                self.broadcast_ack(request_id).await?;

                return Ok(());
            }
            drop(pending);

            // Wait a bit before checking again
            tokio::time::sleep(tokio::time::Duration::from_millis(check_interval_ms)).await;
        }

        // Timeout - request never arrived
        warn!(
            "⏱️ [MAIN_SEQUENCER] Timeout waiting for request {} (round {}), skipping",
            request_id, round
        );

        Ok(())
    }

    /// Check if consensus has been reached for the current transaction
    pub async fn has_consensus(&self) -> bool {
        let sync_state = self.sync_state.read().await;

        if sync_state.current_processing.is_none() {
            return false;
        }

        let threshold = (sync_state.total_nodes / 2) + 1;
        let agreed_count = sync_state.agreed_nodes.len();
        let has_consensus = agreed_count >= threshold;

        if has_consensus {
            info!(
                "✅ [NETWORK_SEQUENCER] [CONSENSUS] Consensus reached for tx_id={}: {}/{} nodes agreed (threshold: {})",
                sync_state.current_processing.as_ref().unwrap(),
                agreed_count,
                sync_state.total_nodes,
                threshold
            );
        }

        has_consensus
    }

    /// Propose a transaction for processing and wait for consensus
    pub async fn propose_transaction(&self, transaction_id: &str, sequence: u64) -> Result<bool> {
        let mut sync_state = self.sync_state.write().await;

        // Check if we can propose (nothing currently processing or previous is confirmed)
        if let Some(current_tx) = &sync_state.current_processing {
            if !sync_state.is_confirmed {
                info!(
                    "⏳ [NETWORK_SEQUENCER] Cannot propose tx_id={}: previous transaction {} not confirmed yet",
                    transaction_id, current_tx
                );
                return Ok(false);
            }
        }

        // Set as current processing
        sync_state.current_processing = Some(transaction_id.to_string());
        sync_state.current_sequence = sequence;
        sync_state.agreed_nodes.clear();
        sync_state.confirmed_nodes.clear();
        sync_state.is_confirmed = false;

        // Add ourselves to agreed nodes
        sync_state.agreed_nodes.insert(self.node_id.clone());

        drop(sync_state);

        // Broadcast proposal
        if let Some(message_tx) = &self.message_tx {
            let broadcast_data = serde_json::to_vec(
                &crate::types::GossipsubMessage::NetworkTransactionSequencerSync {
                    transaction_id: transaction_id.to_string(),
                    sequence,
                    node_id: self.node_id.clone(),
                    state: "proposed".to_string(),
                },
            )?;

            message_tx
                .send(crate::types::ChannelMessage::Broadcast {
                    topic:
                        crate::network::transport::types::TOPIC_NETWORK_TRANSACTION_SEQUENCER_SYNC
                            .to_string(),
                    data: broadcast_data,
                })
                .await?;

            info!(
                "📤 [NETWORK_SEQUENCER] Broadcasted proposal for tx_id={}, sequence={}",
                transaction_id, sequence
            );
        }

        Ok(true)
    }

    /// Mark that we're processing the transaction
    pub async fn mark_processing(&self, transaction_id: &str) -> Result<()> {
        if let Some(message_tx) = &self.message_tx {
            let sync_state = self.sync_state.read().await;
            let sequence = sync_state.current_sequence;
            drop(sync_state);

            if sequence == 1 {
                info!(
                    "🧭 [MAIN_SEQUENCER] Processing first transaction in queue: tx_id={}",
                    transaction_id
                );
            }

            let broadcast_data = serde_json::to_vec(
                &crate::types::GossipsubMessage::NetworkTransactionSequencerSync {
                    transaction_id: transaction_id.to_string(),
                    sequence,
                    node_id: self.node_id.clone(),
                    state: "processing".to_string(),
                },
            )?;

            message_tx
                .send(crate::types::ChannelMessage::Broadcast {
                    topic:
                        crate::network::transport::types::TOPIC_NETWORK_TRANSACTION_SEQUENCER_SYNC
                            .to_string(),
                    data: broadcast_data,
                })
                .await?;
        }

        Ok(())
    }

    /// Mark that we've completed processing the transaction
    pub async fn mark_completed(&self, transaction_id: &str) -> Result<()> {
        let mut sync_state = self.sync_state.write().await;

        if sync_state.current_processing.as_ref() == Some(&transaction_id.to_string()) {
            let sequence = sync_state.current_sequence;

            // Add ourselves to confirmed nodes
            sync_state.confirmed_nodes.insert(self.node_id.clone());
            let confirmed_count = sync_state.confirmed_nodes.len();

            info!(
                "✅ [NETWORK_SEQUENCER] [COMPLETE] Marked tx_id={} as completed locally (sequence={}, confirmed: {}/{})",
                transaction_id, sequence, confirmed_count, sync_state.total_nodes
            );

            drop(sync_state);

            // Broadcast completion confirmation
            if let Some(message_tx) = &self.message_tx {
                let broadcast_data = serde_json::to_vec(
                    &crate::types::GossipsubMessage::NetworkTransactionSequencerSync {
                        transaction_id: transaction_id.to_string(),
                        sequence,
                        node_id: self.node_id.clone(),
                        state: "completed".to_string(),
                    },
                )?;

                message_tx
                    .send(crate::types::ChannelMessage::Broadcast {
                        topic: crate::network::transport::types::TOPIC_NETWORK_TRANSACTION_SEQUENCER_SYNC.to_string(),
                        data: broadcast_data,
                    })
                    .await?;

                info!(
                    "📤 [NETWORK_SEQUENCER] [COMPLETE] Broadcasted completion confirmation for tx_id={}",
                    transaction_id
                );
            }

            // Check if we should clear state (all nodes confirmed)
            let mut sync_state = self.sync_state.write().await;
            if sync_state.confirmed_nodes.len() >= sync_state.total_nodes {
                let completed_tx = sync_state.current_processing.clone();
                sync_state.current_processing = None;
                sync_state.agreed_nodes.clear();
                sync_state.confirmed_nodes.clear();
                sync_state.is_confirmed = false;

                // Clear the cached request
                drop(sync_state);
                let mut cache = self.current_request_cache.write().await;
                if let Some(cached_request) = cache.as_ref() {
                    if let Some(ref completed_tx_id) = completed_tx {
                        if cached_request.transaction_id == *completed_tx_id {
                            *cache = None;
                            info!(
                                "🎉 [NETWORK_SEQUENCER] [COMPLETE] ALL nodes confirmed tx_id={}! State and cache cleared, ready for next transaction.",
                                completed_tx_id
                            );
                            info!(
                                "🔓 [NETWORK_SEQUENCER] Released queue token for tx_id={}, allowing dequeue of next request",
                                completed_tx_id
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Cache the request for the current processing transaction
    pub async fn cache_current_request(&self, request: NetworkTransactionRequest) {
        let mut cache = self.current_request_cache.write().await;
        *cache = Some(request);
        info!("💾 [NETWORK_SEQUENCER] Cached request for current processing transaction");
    }

    /// Handle sequencer sync message from another node
    pub async fn handle_sync_message(
        &self,
        transaction_id: String,
        sequence: u64,
        node_id: String,
        state: String,
    ) {
        let mut sync_state = self.sync_state.write().await;

        info!(
            "📨 [NETWORK_SEQUENCER] [SYNC] Received sync message: node={}, tx_id={}, sequence={}, state={}, current_tx={:?}",
            node_id, transaction_id, sequence, state, sync_state.current_processing
        );

        // If this is a "proposed" message, add the node to agreed nodes
        if state == "proposed" || state == "processing" {
            let should_agree = if sync_state.current_processing.as_ref() == Some(&transaction_id) {
                true
            } else if sync_state.current_processing.is_none() {
                // We haven't proposed anything yet - check if we have this transaction in our queue
                drop(sync_state);
                let mut pending = self.pending_requests.write().await;
                if let Some(request) = pending.remove(&transaction_id) {
                    drop(pending);

                    // Cache the request immediately
                    let mut cache = self.current_request_cache.write().await;
                    *cache = Some(request.clone());
                    let cached_tx_id = request.transaction_id.clone();
                    drop(cache);

                    info!(
                        "🔄 [NETWORK_SEQUENCER] [SYNC] We have tx_id={} in queue but haven't proposed yet. Setting as current_processing and agreeing.",
                        transaction_id
                    );

                    sync_state = self.sync_state.write().await;
                    sync_state.current_processing = Some(transaction_id.clone());
                    sync_state.current_sequence = sequence;
                    sync_state.confirmed_nodes.clear();
                    sync_state.is_confirmed = false;
                    sync_state.agreed_nodes.insert(self.node_id.clone());

                    info!(
                        "💾 [NETWORK_SEQUENCER] [SYNC] Cached request for tx_id={} (cached_tx_id={}) after agreeing to proposal",
                        transaction_id, cached_tx_id
                    );

                    true
                } else {
                    drop(pending);
                    sync_state = self.sync_state.write().await;
                    warn!(
                        "⚠️ [NETWORK_SEQUENCER] [SYNC] Received 'proposed' message for tx_id={} but don't have it in queue. This node will not agree.",
                        transaction_id
                    );
                    false
                }
            } else {
                false
            };

            if should_agree {
                let node_id_clone = node_id.clone();
                let was_new = sync_state.agreed_nodes.insert(node_id);
                if was_new {
                    info!(
                        "✅ [NETWORK_SEQUENCER] [SYNC] Node {} agreed to process tx_id={} (agreed: {}/{}, threshold: {})",
                        node_id_clone,
                        transaction_id,
                        sync_state.agreed_nodes.len(),
                        sync_state.total_nodes,
                        (sync_state.total_nodes / 2) + 1
                    );
                }
            }
        } else if state == "completed" {
            // Track which nodes have confirmed completion
            if sync_state.current_processing.as_ref() == Some(&transaction_id) {
                let node_id_clone = node_id.clone();
                let was_new = sync_state.confirmed_nodes.insert(node_id);
                let confirmed_count = sync_state.confirmed_nodes.len();

                if was_new {
                    info!(
                        "✅ [NETWORK_SEQUENCER] [SYNC] Node {} confirmed completion of tx_id={} (confirmed: {}/{})",
                        node_id_clone, transaction_id, confirmed_count, sync_state.total_nodes
                    );

                    // Check if all nodes have confirmed
                    if confirmed_count >= sync_state.total_nodes {
                        sync_state.is_confirmed = true;
                        sync_state.current_processing = None;
                        sync_state.agreed_nodes.clear();
                        sync_state.confirmed_nodes.clear();
                        sync_state.is_confirmed = false;

                        // Clear the cached request
                        drop(sync_state);
                        let mut cache = self.current_request_cache.write().await;
                        let tx_id_for_log = transaction_id.clone();
                        if let Some(cached_request) = cache.as_ref() {
                            if cached_request.transaction_id == transaction_id {
                                *cache = None;
                            }
                        }
                        drop(cache);

                        // CRITICAL: Increment round and clear selection state for next transaction
                        let mut round_lock = self.main_sequencer_round.write().await;
                        let old_round = *round_lock;
                        *round_lock += 1;
                        let new_round = *round_lock;
                        drop(round_lock);

                        // Clear locked request
                        let mut locked = self.locked_request.write().await;
                        *locked = None;
                        drop(locked);

                        // Clear final node cache for old round
                        let mut final_cache = self.final_node_cache.write().await;
                        final_cache.remove(&old_round);
                        drop(final_cache);

                        info!(
                            "🎉 [MAIN_SEQUENCER] [SYNC] ALL nodes confirmed completion of tx_id={}! Round incremented: {} -> {}. State cleared, ready for next transaction.",
                            tx_id_for_log, old_round, new_round
                        );
                        info!(
                            "🔓 [MAIN_SEQUENCER] Released queue token and advanced cursor (round {} -> {})",
                            old_round, new_round
                        );
                    }
                }
            }
        }
    }

    /// Update total nodes count (for consensus threshold)
    pub async fn update_total_nodes(&self, total_nodes: usize) {
        let mut sync_state = self.sync_state.write().await;
        let old_total = sync_state.total_nodes;
        sync_state.total_nodes = total_nodes;
        info!(
            "🔄 [NETWORK_SEQUENCER] [CONFIG] Updated total nodes: {} -> {} (consensus threshold: {})",
            old_total,
            total_nodes,
            (total_nodes / 2) + 1
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;

    fn create_peer_id() -> libp2p::PeerId {
        identity::Keypair::generate_ed25519().public().to_peer_id()
    }

    #[tokio::test]
    async fn vault_sequencer_returns_popped_request_for_final_node() {
        let mut sequencer = ContractTransactionSequencer::new();
        let peer_id = create_peer_id();
        sequencer.set_local_peer_id(peer_id);
        sequencer.final_node_cache.write().await.insert(0, peer_id);

        let request = ContractTransactionRequest {
            flow: ContractTransactionFlow::SolverAddLiquidity {
                solver_address: "solver".to_string(),
                solver_id: "solver-1".to_string(),
                asset_chain_name: "eth".to_string(),
                amount: 100,
            },
            transaction_id: "vault-tx-1".to_string(),
            sequence: 1,
        };

        sequencer
            .pending_requests
            .write()
            .await
            .insert(request.transaction_id.clone(), request.clone());

        let next = sequencer.get_next_request().await;

        assert!(next.is_some());
        let next = next.unwrap();
        assert_eq!(next.transaction_id, "vault-tx-1");
        assert!(sequencer.pending_requests.read().await.is_empty());
    }

    #[tokio::test]
    async fn main_sequencer_returns_popped_request_for_final_node() {
        let mut sequencer = NetworkTransactionSequencer::new();
        let peer_id = create_peer_id();
        sequencer.set_local_peer_id(peer_id);
        sequencer.final_node_cache.write().await.insert(0, peer_id);

        let request = NetworkTransactionRequest {
            flow: NetworkTransactionFlow::NetworkToTarget {
                intent: DepositIntent {
                    source_address: "source".to_string(),
                    target_address: "target".to_string(),
                    source_chain: "chain_a".to_string(),
                    target_chain: "chain_b".to_string(),
                    amount: 10,
                    source_token: "TOKENA".to_string(),
                    target_token: "TOKENB".to_string(),
                    timestamp: 0,
                },
                intent_hash: "hash".to_string(),
                transaction_type: TransactionType::NetworkToTarget,
                amount: 10,
                tx_bytes: vec![],
                eth_tx: crate::chain_abstraction::EthereumTransaction {
                    to: "addr".to_string(),
                    value: "0".to_string(),
                    gas_limit: 0,
                    gas_price: "0".to_string(),
                    nonce: 0,
                    data: None,
                    chain_id: 1,
                },
                user_tweaked_share: None,
                user_eth_address: None,
            },
            transaction_id: "main-tx-1".to_string(),
            sequence: 1,
        };

        sequencer
            .pending_requests
            .write()
            .await
            .insert(request.transaction_id.clone(), request.clone());

        let next = sequencer.get_next_request().await;

        assert!(next.is_some());
        let next = next.unwrap();
        assert_eq!(next.transaction_id, "main-tx-1");
        assert!(sequencer.pending_requests.read().await.is_empty());
    }
}
