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
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::types::{DepositIntent, TransactionType};

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
}

/// Sequencer for contract transactions
/// 
/// Production-ready implementation that ensures sequential processing to prevent nonce collisions.
/// Synchronizes across all nodes to prevent VRF round overlaps.
/// Uses deterministic ordering (sorted by transaction_id) to ensure all nodes process the same transaction.
/// 
/// CRITICAL: All nodes must have the same requests and process them in the same order.
/// This is ensured by:
/// 1. All nodes receive the same transaction requests (via gossip)
/// 2. All nodes use deterministic ordering (lowest transaction_id) to select the next transaction
/// 3. All nodes use consensus to agree on which transaction to process next
/// 4. All nodes wait for all confirmations before moving to the next transaction
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
}

impl ContractTransactionSequencer {
    /// Create a new sequencer
    /// 
    /// The sequencer queues contract transaction requests for sequential processing.
    /// Processing is done by the MpcNetworkLayer which has direct access to all required components.
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
            })),
            message_tx: None,
            node_id: String::new(),
            current_request_cache: Arc::new(RwLock::new(None)),
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

    /// Initialize the sequencer with network components
    pub async fn initialize(&mut self, message_tx: mpsc::Sender<crate::types::ChannelMessage>, node_id: String, total_nodes: usize) {
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
            ContractTransactionFlow::SolverAddLiquidity { solver_address, asset_chain_name, amount, .. } => {
                format!("solver_add_liquidity:{}:{}:{}", solver_address, asset_chain_name, amount)
            }
        };
        
        // CRITICAL: Hold both locks together to ensure atomic sequence assignment and queue insertion
        // This prevents race conditions where:
        // 1. Multiple requests could get the same sequence (prevented by sync_state lock)
        // 2. Requests could be added to queue out of sequence order (prevented by holding both locks)
        let (sequence, _queue_size) = {
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
            pending.insert(final_transaction_id, request);
            let queue_size = pending.len();
            
            info!(
                "📥 [SEQUENCER] [DETERMINISTIC] Queued transaction: tx_id={}, flow={}, sequence={}, queue_size={}",
                final_tx_id_for_log, flow_description, sequence, queue_size
            );
            info!(
                "📋 [SEQUENCER] [DETERMINISTIC] Queue state (sorted by tx_id): {:?}",
                pending.iter().map(|(tx_id, r)| (tx_id.clone(), r.sequence)).collect::<Vec<_>>()
            );
            
            (sequence, queue_size)
        }; // Both locks released here
        
        Ok(())
    }

    /// Get the current processing transaction info (if any)
    /// Returns (tx_id, sequence, is_confirmed) if we're processing something
    pub async fn get_current_processing(&self) -> Option<(String, u64, bool)> {
        let sync_state = self.sync_state.read().await;
        if let Some(tx_id) = &sync_state.current_processing {
            Some((tx_id.clone(), sync_state.current_sequence, sync_state.is_confirmed))
        } else {
            None
        }
    }

    /// Get the request for the current processing transaction
    /// First checks the cache (if we proposed it), then checks the queue (if we received a "proposed" message)
    pub async fn get_current_request(&self) -> Option<ContractTransactionRequest> {
        // First, check if we have it cached (we proposed it)
        {
            let mut cache = self.current_request_cache.write().await;
            if let Some(request) = cache.take() {
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

    /// Get the next request to process based on FCFS ordering
    /// Returns None if something is currently being processed or not confirmed yet
    pub async fn get_next_request(&self) -> Option<ContractTransactionRequest> {
        let sync_state = self.sync_state.read().await;
        
        // CRITICAL: Don't move to next until previous is confirmed by all nodes
        if let Some(current_tx) = &sync_state.current_processing {
            if !sync_state.is_confirmed {
                info!(
                    "⏳ [SEQUENCER] [FCFS] Waiting for confirmation: current_tx={}, confirmed_nodes={}/{}, is_confirmed={}",
                    current_tx,
                    sync_state.confirmed_nodes.len(),
                    sync_state.total_nodes,
                    sync_state.is_confirmed
                );
                return None;
            }
            info!(
                "✅ [SEQUENCER] [FCFS] Previous transaction {} confirmed, ready for next",
                current_tx
            );
        }
        
        drop(sync_state);
        
        // Get the request with the lowest transaction_id (deterministic ordering)
        // BTreeMap maintains sorted order, so first entry is the lowest transaction_id
        let mut pending = self.pending_requests.write().await;
        if let Some((tx_id, request)) = pending.pop_first() {
            let sequence = request.sequence;
            let queue_size = pending.len();
            info!(
                "🎯 [SEQUENCER] [DETERMINISTIC] Selected next request: tx_id={}, sequence={}, remaining_in_queue={} (lowest tx_id)",
                tx_id, sequence, queue_size
            );
            Some(request)
        } else {
            // info!("📭 [SEQUENCER] [DETERMINISTIC] No pending requests in queue");
            None
        }
    }

    /// Handle sequencer sync message from another node
    pub async fn handle_sync_message(&self, transaction_id: String, sequence: u64, node_id: String, state: String) {
        let mut sync_state = self.sync_state.write().await;
        
        info!(
            "📨 [SEQUENCER] [SYNC] Received sync message: node={}, tx_id={}, sequence={}, state={}, current_tx={:?}",
            node_id, transaction_id, sequence, state, sync_state.current_processing
        );
        
        // If this is a "proposed" message, add the node to agreed nodes
        if state == "proposed" || state == "processing" {
            // Check if this is the transaction we're currently processing (or should be processing)
            let should_agree = if sync_state.current_processing.as_ref() == Some(&transaction_id) {
                // We're already processing this transaction
                true
            } else if sync_state.current_processing.is_none() {
                // We haven't proposed anything yet - check if we have this transaction in our queue
                let pending = self.pending_requests.read().await;
                let has_transaction = pending.contains_key(&transaction_id);
                drop(pending);
                
                if has_transaction {
                    // We have this transaction in our queue - set it as current_processing and agree
                    info!(
                        "🔄 [SEQUENCER] [SYNC] We have tx_id={} in queue but haven't proposed yet. Setting as current_processing and agreeing.",
                        transaction_id
                    );
                    sync_state.current_processing = Some(transaction_id.clone());
                    sync_state.current_sequence = sequence;
                    // DON'T clear agreed_nodes here - other nodes may have already agreed!
                    // Only clear confirmed_nodes and is_confirmed
                    sync_state.confirmed_nodes.clear();
                    sync_state.is_confirmed = false;
                    // Add ourselves to agreed_nodes (don't clear it)
                    sync_state.agreed_nodes.insert(self.node_id.clone());
                    true
                } else {
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
            } else {
                warn!(
                    "⚠️ [SEQUENCER] [SYNC] Node {} proposed tx_id={} but we're processing {:?} or don't have it in queue",
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
                        
                        info!(
                            "🎉 [SEQUENCER] [SYNC] ALL nodes confirmed completion of tx_id={}! State cleared, ready for next transaction.",
                            transaction_id
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
            let broadcast_data = serde_json::to_vec(&crate::types::GossipsubMessage::SequencerSync {
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
            
            let broadcast_data = serde_json::to_vec(&crate::types::GossipsubMessage::SequencerSync {
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
                let broadcast_data = serde_json::to_vec(&crate::types::GossipsubMessage::SequencerSync {
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

