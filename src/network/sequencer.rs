/// Contract Transaction Sequencer
///
/// This module provides a sequencer to ensure contract transactions are executed
/// sequentially to prevent nonce collisions when multiple transactions are processed in parallel.
///
/// CRITICAL: This sequencer synchronizes processing across all nodes to prevent VRF round overlaps.
/// All nodes must process the same request at the same time using deterministic ordering.
use anyhow::Result;
use hex;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint};
use serde::de::Error;
use serde::{Deserializer, Serializer};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, Notify, RwLock};
use tracing::{debug, error, info, warn};

use crate::database::VrfStorage;
use crate::types::{ConsensusMessage, DepositIntent, GossipsubMessage, TransactionType};
use crate::vrf::service::VrfRoundSyncKind;

/// Serialize Option<ProjectivePoint> using SEC1 encoding (compressed format)
fn serialize_vault_group_key<S>(
    key: &Option<ProjectivePoint>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match key {
        Some(point) => {
            // Convert ProjectivePoint to AffinePoint for encoding
            let affine = AffinePoint::from(*point);
            // Serialize as compressed SEC1 encoded bytes (33 bytes)
            let ep = affine.to_encoded_point(true);
            serializer.serialize_some(ep.as_bytes())
        }
        None => serializer.serialize_none(),
    }
}

/// Deserialize Option<ProjectivePoint> from SEC1 encoded bytes
fn deserialize_vault_group_key<'de, D>(deserializer: D) -> Result<Option<ProjectivePoint>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Visitor;
    use std::fmt;

    struct OptionPointVisitor;

    impl<'de> Visitor<'de> for OptionPointVisitor {
        type Value = Option<ProjectivePoint>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an optional secp256k1 point in compressed SEC1 format")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(PointBytesVisitor)
        }
    }

    struct PointBytesVisitor;

    impl<'de> Visitor<'de> for PointBytesVisitor {
        type Value = Option<ProjectivePoint>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a secp256k1 point in compressed SEC1 format")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let ep =
                EncodedPoint::from_bytes(v).map_err(|_| E::custom("invalid SEC1 encoded point"))?;
            let affine: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
            let affine = affine.ok_or_else(|| E::custom("invalid point on curve"))?;
            // Convert AffinePoint to ProjectivePoint
            Ok(Some(ProjectivePoint::from(affine)))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut bytes = Vec::with_capacity(33);
            while let Some(b) = seq.next_element()? {
                bytes.push(b);
            }
            self.visit_bytes(&bytes)
        }
    }

    deserializer.deserialize_option(OptionPointVisitor)
}

/// Enum to distinguish between different contract transaction flows
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ContractTransactionFlow {
    /// Deposit intent transactions (UserToVault, NetworkToTarget, VaultToNetwork)
    DepositIntent {
        intent: DepositIntent,
        intent_hash: String,
        transaction_type: TransactionType,
        #[serde(
            serialize_with = "serialize_vault_group_key",
            deserialize_with = "deserialize_vault_group_key"
        )]
        vault_group_key: Option<ProjectivePoint>, // Serialized using SEC1 encoding for network transmission
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
    /// Refund intent contract call
    RefundIntent {
        intent_id: String,
        transaction_hash: String,
        timestamp: String,
        reason: String,
        #[serde(
            serialize_with = "serialize_vault_group_key",
            deserialize_with = "deserialize_vault_group_key"
        )]
        vault_group_key: Option<ProjectivePoint>, // Serialized using SEC1 encoding for network transmission
    },
}

/// Request to execute a contract transaction
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    /// Sequence number for the current processing transaction (leader-assigned from SELECT)
    current_sequence: u64,
    /// Global sequence counter for FCFS ordering (leader uses this to assign sequence in SELECT)
    global_sequence: u64,
    /// Last committed sequence number (monotonic, advances only on COMMIT_CERT)
    last_committed_sequence: u64,
    /// Current view ID (membership epoch, increments on membership change)
    view_id: u64,
    /// Nodes that have agreed to process the current request
    agreed_nodes: HashSet<String>,
    /// Nodes that have confirmed completion of the current request
    confirmed_nodes: HashSet<String>,
    /// Total number of active nodes (for consensus threshold)
    total_nodes: usize,
    /// Whether current transaction is confirmed (all nodes confirmed) - DEPRECATED: use COMMIT_CERT instead
    is_confirmed: bool,
    /// Transactions that were proposed before we had the full request
    missing_requests: HashSet<String>,
    /// Processed transactions for idempotency: (round, request_id)
    processed: HashSet<(u64, String)>,
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
    pub(crate) pending_requests: Arc<RwLock<BTreeMap<String, ContractTransactionRequest>>>,
    /// Synchronization state
    sync_state: Arc<RwLock<SequencerSyncState>>,
    /// Message channel for broadcasting sequencer sync messages
    message_tx: Option<mpsc::Sender<crate::types::ChannelMessage>>,
    /// Local node ID
    node_id: String,
    /// Cached request for the current processing transaction (set when we propose it)
    current_request_cache: Arc<RwLock<Option<ContractTransactionRequest>>>,
    /// Cache of completed requests for retry purposes (kept for a period after completion)
    completed_requests_cache: Arc<RwLock<HashMap<String, ContractTransactionRequest>>>,
    /// Notify waiting tasks when queue state changes
    work_notify: Arc<Notify>,

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
    /// Tracks rounds for which THIS node has performed VRF selection
    /// This prevents skipping VRF when consensus results arrive from other nodes first
    vault_vrf_performed_rounds: Arc<RwLock<HashSet<u64>>>,
    /// Track when we started waiting for SELECT message (to detect timeouts)
    select_wait_start_time: Arc<RwLock<Option<std::time::SystemTime>>>,
    /// Track when we started waiting for confirmations (to detect timeouts)
    confirmation_wait_start_time: Arc<RwLock<Option<std::time::SystemTime>>>,
    /// Per-request exclusion list: tracks peers that have timed out repeatedly
    /// Format: request_id -> set of excluded peer_ids
    peer_exclusions: Arc<RwLock<HashMap<String, HashSet<libp2p::PeerId>>>>,
    /// Per-peer timeout counts: tracks how many times each peer has timed out per request
    /// Format: (request_id, peer_id) -> timeout_count
    peer_timeout_counts: Arc<RwLock<HashMap<(String, libp2p::PeerId), u32>>>,
    /// DONE_ACK collection: tracks acks received for (round, request_id)
    /// Format: (round, request_id) -> HashSet<PeerId>
    pub(crate) done_acks: Arc<RwLock<HashMap<(u64, String), HashSet<libp2p::PeerId>>>>,
    /// Current leader (final_node_id) for the current processing transaction
    pub(crate) current_leader: Arc<RwLock<Option<libp2p::PeerId>>>,
    /// Pending DONE_ACKs that need resending: (sequence, request_id) -> (round, view_id, leader_peer_id, last_sent)
    /// Resend every 2s until COMMIT_CERT received
    pending_done_acks: Arc<RwLock<HashMap<(u64, String), (u64, u64, libp2p::PeerId, std::time::SystemTime)>>>,
}

/// HRW (Highest Random Weight) / Rendezvous Hashing helper functions
/// These functions provide deterministic leader selection without consensus

/// Compute HRW score for a peer given request_id, round, and peer_id
/// Score = SHA256(request_id || round || peer_id)
fn compute_hrw_score(request_id: &str, round: u64, peer_id: &libp2p::PeerId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_bytes());
    hasher.update(round.to_be_bytes());
    hasher.update(peer_id.to_bytes());
    hasher.finalize().into()
}

/// Get eligible candidates by filtering out excluded peers
/// Returns sorted list for deterministic ordering
fn get_eligible_candidates(
    available_nodes: &[libp2p::PeerId],
    excluded: &HashSet<libp2p::PeerId>,
) -> Vec<libp2p::PeerId> {
    let mut candidates: Vec<libp2p::PeerId> = available_nodes
        .iter()
        .filter(|peer_id| !excluded.contains(peer_id))
        .cloned()
        .collect();
    
    // Sort deterministically by peer_id bytes for consistent ordering
    candidates.sort_by(|a, b| a.to_bytes().cmp(&b.to_bytes()));
    candidates
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
                last_committed_sequence: 0,
                view_id: 0,
                agreed_nodes: HashSet::new(),
                confirmed_nodes: HashSet::new(),
                total_nodes: 0,
                is_confirmed: false,
                missing_requests: HashSet::new(),
                processed: HashSet::new(),
            })),
            message_tx: None,
            node_id: String::new(),
            current_request_cache: Arc::new(RwLock::new(None)),
            completed_requests_cache: Arc::new(RwLock::new(HashMap::new())),
            work_notify: Arc::new(Notify::new()),

            // Initialize VRF + Consensus fields
            local_peer_id: None,
            vault_sequencer_round: Arc::new(RwLock::new(0)),
            vrf_service: None,
            consensus_node: None,
            available_nodes: Arc::new(RwLock::new(Vec::new())),
            final_node_cache: Arc::new(RwLock::new(HashMap::new())),
            locked_request: Arc::new(RwLock::new(None)),
            vault_vrf_performed_rounds: Arc::new(RwLock::new(HashSet::new())),
            select_wait_start_time: Arc::new(RwLock::new(None)),
            confirmation_wait_start_time: Arc::new(RwLock::new(None)),
            peer_exclusions: Arc::new(RwLock::new(HashMap::new())),
            peer_timeout_counts: Arc::new(RwLock::new(HashMap::new())),
            done_acks: Arc::new(RwLock::new(HashMap::new())),
            current_leader: Arc::new(RwLock::new(None)),
            pending_done_acks: Arc::new(RwLock::new(HashMap::new())),
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

    /// Select leader deterministically using HRW (Highest Random Weight) / Rendezvous Hashing
    /// Returns ordered list of top-N leaders for failover support
    /// 
    /// Algorithm:
    /// - score(p) = hash(request_id || round || peer_id)
    /// - leader = argmax_p score(p)
    /// - Tie-break: lexicographically smallest peer_id
    async fn select_leader_with_hrw(
        &self,
        request_id: &str,
        round: u64,
        max_candidates: usize,
    ) -> Result<Vec<libp2p::PeerId>> {
        // Get eligible candidates (exclude timed-out peers)
        let available = self.available_nodes.read().await.clone();
        let excluded = {
            let exclusions = self.peer_exclusions.read().await;
            exclusions.get(request_id).cloned().unwrap_or_default()
        };
        let candidates = get_eligible_candidates(&available, &excluded);

        if candidates.is_empty() {
            return Err(anyhow::anyhow!("No eligible candidates for HRW selection"));
        }

        // Compute HRW scores for all candidates
        let mut scored: Vec<(libp2p::PeerId, [u8; 32])> = candidates
            .iter()
            .map(|peer_id| {
                let score = compute_hrw_score(request_id, round, peer_id);
                (*peer_id, score)
            })
            .collect();

        // Sort by score (descending), then by peer_id (ascending) for tie-break
        scored.sort_by(|a, b| {
            match b.1.cmp(&a.1) {
                // Descending by score
                std::cmp::Ordering::Equal => {
                    // Tie-break: lexicographically smallest peer_id
                    a.0.to_bytes().cmp(&b.0.to_bytes())
                }
                other => other,
            }
        });

        // Return top-N leaders
        let leaders: Vec<libp2p::PeerId> = scored
            .into_iter()
            .take(max_candidates)
            .map(|(peer_id, _)| peer_id)
            .collect();

        info!(
            "🎯 [VAULT_SEQUENCER] HRW selected {} leader(s) for request_id={}, round={}: {:?}",
            leaders.len(),
            request_id,
            round,
            leaders.iter().map(|p| p.to_string()).collect::<Vec<_>>()
        );

        Ok(leaders)
    }

    /// Record a timeout for a peer on a specific request
    /// If timeout count exceeds threshold (default: 3), peer is excluded from HRW selection
    pub async fn record_peer_timeout(&self, request_id: &str, peer_id: libp2p::PeerId, timeout_threshold: u32) {
        let mut timeout_counts = self.peer_timeout_counts.write().await;
        let key = (request_id.to_string(), peer_id);
        let count = timeout_counts.entry(key.clone()).or_insert(0);
        *count += 1;

        if *count >= timeout_threshold {
            let mut exclusions = self.peer_exclusions.write().await;
            exclusions.entry(request_id.to_string())
                .or_insert_with(HashSet::new)
                .insert(peer_id);
            warn!(
                "⚠️ [VAULT_SEQUENCER] Peer {} excluded from HRW for request {} ({} timeouts >= threshold {})",
                peer_id, request_id, count, timeout_threshold
            );
        } else {
            info!(
                "📊 [VAULT_SEQUENCER] Peer {} timeout count for request {}: {}/{}",
                peer_id, request_id, count, timeout_threshold
            );
        }
    }

    /// Clear exclusion and timeout counts for a completed request
    pub async fn clear_request_exclusions(&self, request_id: &str) {
        let mut exclusions = self.peer_exclusions.write().await;
        exclusions.remove(request_id);
        
        let mut timeout_counts = self.peer_timeout_counts.write().await;
        timeout_counts.retain(|(req_id, _), _| req_id != request_id);
        
        info!("🧹 [VAULT_SEQUENCER] Cleared exclusions for completed request {}", request_id);
    }

    /// Compute quorum threshold using ceil(2N/3) formula
    /// CRITICAL: Uses ceil, not floor, to ensure safety
    /// Formula: max(2, (2 * total_nodes + 2) / 3)
    /// Examples:
    ///   - N=3: quorum = 2 (ceil(6/3)=2)
    ///   - N=4: quorum = 3 (ceil(8/3)=3, NOT 2)
    ///   - N=5: quorum = 4 (ceil(10/3)=4, NOT 3)
    ///   - N=7: quorum = 5 (ceil(14/3)=5, NOT 4)
    pub fn compute_quorum_threshold(total_nodes: usize) -> usize {
        if total_nodes == 0 {
            return 0;
        }
        // Integer ceil for 2N/3: (2*n + 2) / 3
        let quorum = (2 * total_nodes + 2) / 3;
        // Minimum 2 nodes for 3-node cluster
        quorum.max(2)
    }

    /// Get total nodes count
    pub async fn get_total_nodes(&self) -> usize {
        let sync_state = self.sync_state.read().await;
        sync_state.total_nodes
    }

    /// Get current view_id
    pub async fn get_view_id(&self) -> u64 {
        let sync_state = self.sync_state.read().await;
        sync_state.view_id
    }

    /// Get local peer ID
    pub fn get_local_peer_id(&self) -> Option<libp2p::PeerId> {
        self.local_peer_id
    }

    /// Get resync data for RESYNC_RESPONSE
    pub async fn get_resync_data(&self) -> (
        u64, // view_id
        u64, // round
        Option<(u64, String)>, // last_committed: (sequence, request_id)
        Option<(u64, String, u64, libp2p::PeerId)>, // current_processing: (sequence, request_id, round, leader_id)
        Vec<String>, // pending_head
    ) {
        let sync_state = self.sync_state.read().await;
        let view_id = sync_state.view_id;
        let last_committed_seq = sync_state.last_committed_sequence;
        let current_seq = sync_state.current_sequence;
        let current_processing = sync_state.current_processing.clone();
        drop(sync_state);
        
        let round = *self.vault_sequencer_round.read().await;
        let current_leader = self.current_leader.read().await.clone();
        
        // Get pending head (top 10 request IDs)
        let pending = self.pending_requests.read().await;
        let pending_head: Vec<String> = pending.keys().take(10).cloned().collect();
        drop(pending);
        
        let last_committed = if last_committed_seq > 0 {
            // We don't track request_id for committed sequences, so return None
            // In production, maintain a mapping
            None
        } else {
            None
        };
        
        let current_processing_tuple = if let Some(ref req_id) = current_processing {
            current_leader.map(|leader| (current_seq, req_id.clone(), round, leader))
        } else {
            None
        };
        
        (view_id, round, last_committed, current_processing_tuple, pending_head)
    }

    /// Select final node deterministically for current round using VRF + Consensus
    /// Returns the peer ID of the selected node (from consensus cache)
    /// 
    /// DEPRECATED: Use select_leader_with_hrw() instead
    #[allow(dead_code)]
    async fn select_final_node(&self) -> Result<libp2p::PeerId> {
        let round = *self.vault_sequencer_round.read().await;

        // Check if consensus has completed for this round
        {
            let cache = self.final_node_cache.read().await;
            if let Some(final_node) = cache.get(&round) {
                return Ok(*final_node);
            }
        }

        // Fallback: pull the validated consensus result from the consensus node (mirrors signing flow)
        if let Some(consensus) = &self.consensus_node {
            let consensus_guard = consensus.read().await;
            if let Some(result) = consensus_guard.get_consensus_result(round) {
                let mut cache = self.final_node_cache.write().await;
                cache.insert(round, result.final_node.0);
                return Ok(result.final_node.0);
            }
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

            // Mark this round as VRF-performed to prevent re-triggering
            self.vault_vrf_performed_rounds.write().await.insert(round);
            info!(
                "🎯 [VAULT_SEQUENCER] Round {} VRF COMPLETE: This node has performed and broadcasted its VRF selection",
                round
            );
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

            // Broadcast the consensus result to other nodes
            if let Some(message_tx) = &self.message_tx {
                let consensus_msg = ConsensusMessage::FinalNodeResult {
                    result: result.clone(),
                    round,
                };

                // Wrap in GossipsubMessage::Consensus for proper deserialization
                let gossipsub_msg = GossipsubMessage::Consensus(consensus_msg);
                let broadcast_data = serde_json::to_vec(&gossipsub_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize consensus message: {}", e))?;

                message_tx
                    .send(crate::types::ChannelMessage::Broadcast {
                        topic: "consensus-result".to_string(),
                        data: broadcast_data,
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to broadcast consensus result: {}", e))?;

                info!(
                    "📤 [VAULT_SEQUENCER] Broadcasted consensus result for round {}",
                    round
                );
            } else {
                warn!("⚠️ [VAULT_SEQUENCER] No message channel available to broadcast consensus result");
            }

            // Cache final node for this round
            let mut cache = self.final_node_cache.write().await;
            cache.insert(round, result.final_node.0);

            Ok(result)
        } else {
            Err(anyhow::anyhow!("Consensus node not available"))
        }
    }

    /// Check if current node is the final node for this round
    /// Check if this node is the final node for a given request using HRW
    pub async fn am_i_final_node_for_request(&self, request_id: &str, round: u64) -> Result<bool> {
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        // Use HRW to compute leaders
        let leaders = self.select_leader_with_hrw(request_id, round, 1).await?;
        
        if leaders.is_empty() {
            return Err(anyhow::anyhow!("No leaders computed for request_id={}", request_id));
        }

        let final_node = leaders[0];
        let is_final = local_peer == final_node;

        if is_final {
            info!(
                "✅ [VAULT_SEQUENCER] am_i_final_node_for_request() = true: local_peer={:?}, final_node={:?}, request_id={}, round={}",
                local_peer, final_node, request_id, round
            );
        } else {
            debug!(
                "🔍 [VAULT_SEQUENCER] am_i_final_node_for_request() = false: local_peer={:?}, final_node={:?}, request_id={}, round={}",
                local_peer, final_node, request_id, round
            );
        }

        Ok(is_final)
    }

    /// Check if this node is the final node (deprecated - use am_i_final_node_for_request instead)
    /// 
    /// DEPRECATED: This method uses old VRF+Consensus approach
    /// Use am_i_final_node_for_request() with request_id and round for HRW-based selection
    #[allow(dead_code)]
    pub async fn am_i_final_node(&self) -> Result<bool> {
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        let final_node = self.select_final_node().await?;
        let is_final = local_peer == final_node;

        if is_final {
            info!(
                "✅ [VAULT_SEQUENCER] am_i_final_node() = true: local_peer={:?}, final_node={:?}",
                local_peer, final_node
            );
        } else {
            debug!(
                "🔍 [VAULT_SEQUENCER] am_i_final_node() = false: local_peer={:?}, final_node={:?}",
                local_peer, final_node
            );
        }

        Ok(is_final)
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

    /// Handle consensus message from another node
    pub async fn handle_consensus_message(
        &self,
        msg: crate::types::ConsensusMessage,
    ) -> Result<()> {
        // Extract round from consensus message
        let crate::types::ConsensusMessage::FinalNodeResult { round, .. } = msg;
        let final_round = Some(round);

        if let Some(consensus) = &self.consensus_node {
            let mut consensus_node = consensus.write().await;
            consensus_node.handle_message(msg).await?;
            info!("✅ [VAULT_SEQUENCER] Handled consensus message");
        } else {
            warn!("⚠️ [VAULT_SEQUENCER] Consensus node not available to handle message");
        }

        // Update the local final-node cache using the consensus result (validated or pending)
        // CRITICAL FIX: Cache consensus for ALL rounds where we have a result, but only if:
        // 1. We performed VRF for this round (definitely ours), OR
        // 2. The round matches our current vault sequencer round (likely ours)
        // This prevents caching signing module rounds while ensuring all nodes can identify the final node
        // NOTE: We cache even pending results - they will be validated when selected_nodes arrive
        if let Some(round) = final_round {
            if let Some(consensus) = &self.consensus_node {
                let consensus_guard = consensus.read().await;
                // get_consensus_result now checks both validated and pending results
                if let Some(result) = consensus_guard.get_consensus_result(round) {
                    // Check if THIS vault sequencer performed VRF for this round
                    let has_performed_vrf = self
                        .vault_vrf_performed_rounds
                        .read()
                        .await
                        .contains(&round);
                    let current_round = *self.vault_sequencer_round.read().await;

                    // CRITICAL FIX: Only cache if THIS vault sequencer performed VRF for this round
                    // Don't cache based on "round == current_round" because signing module
                    // might be at the same round number, and we'd cache ITS consensus result!
                    if has_performed_vrf {
                        // Cache the result (both VALIDATED and PENDING)
                        // Even PENDING results should be cached so the final node can identify itself
                        // The pending_results mechanism in consensus ensures correctness
                        let mut cache = self.final_node_cache.write().await;
                        cache.insert(round, result.final_node.0);
                        let is_pending = consensus_guard.is_result_pending(round);
                        if is_pending {
                            info!(
                                "💾 [VAULT_SEQUENCER] Cached final node {:?} for round {} from consensus message (PENDING - will validate when VRF data arrives) (performed_vrf={}, current_round={})",
                                result.final_node.0, round, has_performed_vrf, current_round
                            );
                        } else {
                            info!(
                                "💾 [VAULT_SEQUENCER] Cached final node {:?} for round {} from consensus message (VALIDATED) (performed_vrf={}, current_round={})",
                                result.final_node.0, round, has_performed_vrf, current_round
                            );
                        }
                    } else {
                        // This round is from another module (signing/main) - ignore it
                        debug!(
                            "🔕 [VAULT_SEQUENCER] Ignoring consensus for round {} - vault sequencer never performed VRF for this round (likely from signing/main module, current={}, performed_vrf={})",
                            round, current_round, has_performed_vrf
                        );
                    }
                } else {
                    // This should rarely happen now - get_consensus_result checks both validated and pending
                    info!(
                        "⏳ [VAULT_SEQUENCER] Consensus message received for round {} but no result found (neither validated nor pending) - will retry when selected_nodes arrive",
                        round
                    );
                }
            }
        }
        Ok(())
    }

    /// Handle VRF selected nodes broadcast from another node
    pub async fn handle_vrf_broadcast(
        &self,
        broadcast: crate::protocols::VrfSelectedNodesBroadcast,
        sender_peer_id: libp2p::PeerId,
        total_nodes: usize,
    ) -> Result<()> {
        if let Some(vrf_service) = &self.vrf_service {
            vrf_service
                .handle_vrf_broadcast(broadcast, sender_peer_id, total_nodes)
                .await?;
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
            ContractTransactionFlow::RefundIntent {
                intent_id,
                transaction_hash,
                reason,
                ..
            } => {
                format!(
                    "refund_intent:{}:{}:{}",
                    intent_id, transaction_hash, reason
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

        // Wake any tasks waiting for new work to arrive
        self.work_notify.notify_waiters();

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

    /// Reinsert a failed transaction request back into the sequencer for retry
    ///
    /// This method is used when a transaction fails during broadcast or execution.
    /// Reinsert a failed transaction back into the sequencer queue for retry.
    /// Simple approach: just add it back to the queue, it will be processed later.
    pub async fn reinsert(&self, transaction_id: &str) -> Result<()> {
        info!(
            "🔄 [SEQUENCER] Attempting to reinsert failed transaction: {}",
            transaction_id
        );

        // Try to find the request in multiple places:
        // 1. current_request_cache (if currently processing)
        // 2. pending_requests (if in queue)
        // 3. completed_requests_cache (if already completed)
        let request_opt = {
            // First check current_request_cache (even if not currently processing, it might still be there)
            let cache = self.current_request_cache.read().await;
            let cache_has_request = cache.is_some();
            let cache_tx_id = cache.as_ref().map(|r| r.transaction_id.clone());
            let request = cache
                .as_ref()
                .filter(|r| r.transaction_id == transaction_id)
                .cloned();
            drop(cache);

            info!(
                "🔍 [SEQUENCER] [REINSERT] Checking current_request_cache for tx_id={}: has_request={}, cache_tx_id={:?}, matches={}",
                transaction_id,
                cache_has_request,
                cache_tx_id,
                request.is_some()
            );

            if request.is_some() {
                info!(
                    "✅ [SEQUENCER] [REINSERT] Transaction {} found in current_request_cache",
                    transaction_id
                );
                request
            } else {
                // Try to find the request in pending_requests
                let pending = self.pending_requests.read().await;
                let pending_contains = pending.contains_key(transaction_id);
                let pending_size = pending.len();
                let request = pending.get(transaction_id).cloned();
                drop(pending);

                info!(
                    "🔍 [SEQUENCER] [REINSERT] Checking pending_requests for tx_id={}: contains={}, pending_size={}, found={}",
                    transaction_id,
                    pending_contains,
                    pending_size,
                    request.is_some()
                );

                if request.is_some() {
                    info!(
                        "✅ [SEQUENCER] [REINSERT] Transaction {} found in pending_requests",
                        transaction_id
                    );
                    request
                } else {
                    // Not in pending, check completed_requests_cache for retry
                    info!(
                        "🔍 [SEQUENCER] [REINSERT] Transaction {} not in pending queue, checking completed requests cache",
                        transaction_id
                    );
                    let completed_cache = self.completed_requests_cache.read().await;
                    let cache_contains = completed_cache.contains_key(transaction_id);
                    let cache_size = completed_cache.len();
                    let request = completed_cache.get(transaction_id).cloned();
                    drop(completed_cache);

                    info!(
                        "🔍 [SEQUENCER] [REINSERT] Checking completed_requests_cache for tx_id={}: contains={}, cache_size={}, found={}",
                        transaction_id,
                        cache_contains,
                        cache_size,
                        request.is_some()
                    );

                    request
                }
            }
        };

        if let Some(request) = request_opt {
            // Check if it's already in pending_requests (avoid duplicates)
            let mut pending = self.pending_requests.write().await;
            if pending.contains_key(transaction_id) {
                info!(
                    "ℹ️ [SEQUENCER] Transaction {} already in pending queue, skipping reinsert",
                    transaction_id
                );
                return Ok(());
            }

            // Add it back to the queue - it will be processed after current transaction completes
            pending.insert(transaction_id.to_string(), request);
            drop(pending);

            info!(
                "✅ [SEQUENCER] Reinserted transaction {} into queue for retry (will be processed after current transaction completes)",
                transaction_id
            );

            // Notify waiters that a new request is available
            self.work_notify.notify_waiters();
        } else {
            warn!(
                "⚠️ [SEQUENCER] [REINSERT] Cannot reinsert transaction {} - not found in any cache (current_request_cache, pending_requests, or completed_requests_cache). This transaction cannot be retried.",
                transaction_id
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

    /// Get confirmation status (confirmed count, total count)
    pub async fn get_confirmation_status(&self) -> Option<(usize, usize)> {
        let sync_state = self.sync_state.read().await;
        if sync_state.current_processing.is_some() {
            Some((sync_state.confirmed_nodes.len(), sync_state.total_nodes))
        } else {
            None
        }
    }

    /// Check if confirmation wait timeout has been exceeded
    pub async fn check_confirmation_timeout(&self, timeout_secs: u64) -> bool {
        let sync_state = self.sync_state.read().await;
        if sync_state.current_processing.is_none() {
            // No transaction being processed, clear wait time
            let mut wait_time = self.confirmation_wait_start_time.write().await;
            *wait_time = None;
            return false;
        }

        if sync_state.is_confirmed {
            // All nodes confirmed, clear wait time
            let mut wait_time = self.confirmation_wait_start_time.write().await;
            *wait_time = None;
            return false;
        }

        let now = std::time::SystemTime::now();
        let mut wait_time = self.confirmation_wait_start_time.write().await;

        if let Some(start_time) = *wait_time {
            if let Ok(elapsed) = now.duration_since(start_time) {
                if elapsed.as_secs() >= timeout_secs {
                    // Timeout exceeded
                    *wait_time = None;
                    return true;
                }
            }
        } else {
            // First time waiting - record start time
            *wait_time = Some(now);
        }

        false
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
            let locked_request_id = {
                let locked = self.locked_request.read().await;
                locked.clone()
            };

            if let Some(request_id) = &locked_request_id {
                // We have a locked request from final node - retrieve and return it
                let mut pending = self.pending_requests.write().await;
                if let Some(request) = pending.remove(request_id) {
                    info!(
                        "🔓 [VAULT_SEQUENCER] Processing locked request from final node: {}",
                        request_id
                    );
                    return Some(request);
                }
                drop(pending);

                // Locked request not in pending_requests - check if it's already being processed
                let sync_state = self.sync_state.read().await;
                let is_current = sync_state.current_processing.as_ref() == Some(request_id);
                drop(sync_state);

                if is_current {
                    // Already being processed - this is fine, return None to wait
                    info!(
                        "ℹ️ [VAULT_SEQUENCER] Locked request {} is already being processed",
                        request_id
                    );
                    return None;
                }

                // Locked request exists but not found - might be stale or missing
                warn!(
                    "⚠️ [VAULT_SEQUENCER] Locked request {} not found in pending_requests and not being processed. May need to wait for it to arrive.",
                    request_id
                );
                // Continue to VRF logic - it will handle waiting or clearing
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

        // Sync round first to ensure all nodes have the same round
        let round = match self.sync_round_with_peers().await {
            Ok(r) => r,
            Err(e) => {
                warn!("⚠️ [VAULT_SEQUENCER] Round sync failed: {}, using local round", e);
                *self.vault_sequencer_round.read().await
            }
        };

        // Get the first request from queue to compute HRW
        let (first_tx_id, first_request) = {
            let pending = self.pending_requests.read().await;
            if let Some((tx_id, request)) = pending.first_key_value() {
                (tx_id.clone(), request.clone())
            } else {
                return None;
            }
        };

        info!(
            "📤 [VAULT_SEQUENCER] Dequeue attempt: round={}, queue_len={}, first_request={}",
            round, queue_len, first_tx_id
        );

        // Use HRW to get top-3 leaders for failover support
        let leaders = match self.select_leader_with_hrw(&first_tx_id, round, 3).await {
            Ok(leaders) => leaders,
            Err(e) => {
                error!(
                    "❌ [VAULT_SEQUENCER] Failed to compute HRW for request {}: {}",
                    first_tx_id, e
                );
                return None;
            }
        };

        if leaders.is_empty() {
            error!("❌ [VAULT_SEQUENCER] No leaders computed for request {}", first_tx_id);
            return None;
        }

        let local_peer = match self.local_peer_id {
            Some(peer) => peer,
            None => {
                error!("❌ [VAULT_SEQUENCER] Local peer ID not set");
                return None;
            }
        };

        // Check if we are the primary leader (leader[0])
        let is_primary_leader = local_peer == leaders[0];
        let leader_index = leaders.iter().position(|&p| p == local_peer);

        if is_primary_leader {
            info!(
                "✅ [VAULT_SEQUENCER] Round {}: HRW selected this node as PRIMARY leader for request {}",
                round, first_tx_id
            );
        } else if let Some(idx) = leader_index {
            info!(
                "🔍 [VAULT_SEQUENCER] Round {}: This node is backup leader #{} for request {} (primary: {:?})",
                round, idx + 1, first_tx_id, leaders[0]
            );
        } else {
            debug!(
                "🔍 [VAULT_SEQUENCER] Round {}: HRW selected another node as leader for request {} (primary: {:?})",
                round, first_tx_id, leaders[0]
            );
        }

        // Check if we are the primary leader
        if is_primary_leader {
            // We are the leader - select the request
            info!(
                "🎯 [VAULT_SEQUENCER] I AM the leader for round {}, selecting transaction",
                round
            );

            let mut pending = self.pending_requests.write().await;
            if let Some((tx_id, request)) = pending.pop_first() {
                let sequence = request.sequence;
                let queue_size = pending.len();
                info!(
                    "🎯 [VAULT_SEQUENCER] Leader selecting request: tx_id={}, sequence={}, remaining={}",
                    tx_id, sequence, queue_size
                );

                // Lock this request
                drop(pending);
                let mut locked = self.locked_request.write().await;
                *locked = Some(tx_id.clone());

                // Broadcast SELECT message
                if let Err(e) = self.broadcast_select_message(&tx_id, &request).await {
                    error!("❌ [VAULT_SEQUENCER] Failed to broadcast SELECT: {}", e);
                    // Clear locked request on failure
                    *locked = None;
                    drop(locked);
                    return None;
                }

                // Clear wait time since we successfully selected
                let mut wait_time = self.select_wait_start_time.write().await;
                *wait_time = None;
                drop(wait_time);

                drop(locked);
                Some(request)
            } else {
                warn!("⚠️ [VAULT_SEQUENCER] Leader but no requests in queue!");
                None
            }
        } else {
                // We are NOT the final node - check if SELECT message already arrived
                let locked_request_id = {
                    let locked = self.locked_request.read().await;
                    locked.clone()
                };

                if let Some(request_id) = &locked_request_id {
                    // CRITICAL FIX: Try to process the locked request immediately instead of deferring
                    // Check if it's in pending_requests
                    let mut pending = self.pending_requests.write().await;
                    if let Some(request) = pending.remove(request_id) {
                        let mut wait_time = self.select_wait_start_time.write().await;
                        *wait_time = None;
                        drop(wait_time);
                        info!(
                            "🔓 [VAULT_SEQUENCER] Processing locked request from final node (non-final node): {}",
                            request_id
                        );
                        return Some(request);
                    }
                    drop(pending);

                    // If not in pending_requests, check if it's already being processed
                    let sync_state = self.sync_state.read().await;
                    let is_current = sync_state.current_processing.as_ref() == Some(request_id);
                    drop(sync_state);

                    if is_current {
                        // Already being processed - this is fine, return None to wait for it to complete
                        let mut wait_time = self.select_wait_start_time.write().await;
                        *wait_time = None;
                        drop(wait_time);
                        info!(
                            "ℹ️ [VAULT_SEQUENCER] Locked request {} is already being processed, waiting for completion",
                            request_id
                        );
                        return None;
                    }

                    // Locked request exists but not in pending_requests and not being processed
                    // This might be a stale lock or the request hasn't arrived yet
                    let mut wait_time = self.select_wait_start_time.write().await;
                    *wait_time = None;
                    drop(wait_time);
                    warn!(
                        "⚠️ [VAULT_SEQUENCER] Locked request {} not found in pending_requests and not being processed. May be stale or missing.",
                        request_id
                    );
                    // Return None - the locked request check at line 1002 will handle it on next iteration
                    None
                } else {
                    // No SELECT message yet - wait for it with failover support
                    // Track wait time and add timeout
                    let mut wait_time = self.select_wait_start_time.write().await;
                    let now = std::time::SystemTime::now();
                    let timeout_seconds = 10; // Failover timeout: 10 seconds
                    
                    let should_failover = if let Some(start) = *wait_time {
                        if let Ok(elapsed) = now.duration_since(start) {
                            elapsed.as_secs() >= timeout_seconds
                        } else {
                            false
                        }
                    } else {
                        // First time waiting - record start time
                        *wait_time = Some(now);
                        false
                    };
                    drop(wait_time);

                    // Failover: If we're a backup leader and primary timed out, take over
                    if should_failover {
                        // Record timeout for primary leader
                        self.record_peer_timeout(&first_tx_id, leaders[0], 3).await;
                        
                        if let Some(backup_idx) = leader_index {
                            if backup_idx > 0 && backup_idx < leaders.len() {
                                // Check if all previous leaders have failed (we can detect this by timeout)
                                let all_previous_failed = (0..backup_idx).all(|i| {
                                    // In a real implementation, we'd check if leaders[i] is actually down
                                    // For now, we assume timeout means failure
                                    true
                                });

                                if all_previous_failed {
                                    warn!(
                                        "🔄 [VAULT_SEQUENCER] FAILOVER: Primary leader {:?} timed out after {}s. Backup leader #{} (this node) taking over for request {}",
                                        leaders[0], timeout_seconds, backup_idx + 1, first_tx_id
                                    );

                                    // We are now the acting leader - select the request
                                    let mut pending = self.pending_requests.write().await;
                                    if let Some((tx_id, request)) = pending.pop_first() {
                                        let mut locked = self.locked_request.write().await;
                                        *locked = Some(tx_id.clone());

                                        // Broadcast SELECT message
                                        if let Err(e) = self.broadcast_select_message(&tx_id, &request).await {
                                            error!("❌ [VAULT_SEQUENCER] Failed to broadcast SELECT (failover): {}", e);
                                            *locked = None;
                                            drop(locked);
                                            return None;
                                        }

                                        // Clear wait time
                                        let mut wait_time = self.select_wait_start_time.write().await;
                                        *wait_time = None;
                                        drop(wait_time);
                                        drop(locked);
                                        return Some(request);
                                    }
                                }
                            }
                        }

                        // Timeout but we're not a backup leader or failover not applicable
                        error!(
                            "❌ [VAULT_SEQUENCER] TIMEOUT: Waiting for SELECT message for {} seconds! Primary leader {:?} may have failed. Round={}, Request={}",
                            timeout_seconds,
                            leaders[0],
                            round,
                            first_tx_id
                        );
                        // Reset wait time to avoid spam
                        let mut wait_time = self.select_wait_start_time.write().await;
                        *wait_time = Some(now);
                        drop(wait_time);
                    } else {
                        if let Some(idx) = leader_index {
                            if idx > 0 {
                                info!(
                                    "⏳ [VAULT_SEQUENCER] Backup leader #{} waiting for SELECT from primary {:?}...",
                                    idx + 1, leaders[0]
                                );
                            } else {
                                info!(
                                    "⏳ [VAULT_SEQUENCER] Not a leader, waiting for SELECT message from primary {:?}...",
                                    leaders[0]
                                );
                            }
                        } else {
                            info!(
                                "⏳ [VAULT_SEQUENCER] Not a leader, waiting for SELECT message from primary {:?}...",
                                leaders[0]
                            );
                        }
                    }
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
            ContractTransactionFlow::RefundIntent {
                intent_id,
                transaction_hash,
                reason,
                ..
            } => {
                format!(
                    "RefundIntent(intent_id={}, tx_hash={}, reason={})",
                    intent_id, transaction_hash, reason
                )
            }
        };

        // CRITICAL: Leader assigns sequence (single source of truth)
        let (sequence, view_id) = {
            let mut sync_state = self.sync_state.write().await;
            sync_state.global_sequence += 1;
            let seq = sync_state.global_sequence;
            let vid = sync_state.view_id;
            (seq, vid)
        };

        // Create signature (simplified - in production use proper signing)
        let signature = vec![]; // TODO: Sign with node's private key

        // Broadcast via message channel
        if let Some(tx) = &self.message_tx {
            let msg = crate::types::ChannelMessage::Broadcast {
                topic: "vault-sequencer-select".to_string(),
                data: serde_json::to_vec(&crate::types::GossipsubMessage::VaultSequencerSelect {
                    round,
                    request_id: request_id.to_string(),
                    sequence,        // CRITICAL: Leader-assigned sequence
                    view_id,         // Current view ID
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
        sequence: u64,
        view_id: u64,
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

        // Verify view_id (allow higher view_id to trigger resync)
        let mut sync_state = self.sync_state.write().await;
        if view_id < sync_state.view_id {
            warn!(
                "⚠️ [VAULT_SEQUENCER] SELECT with stale view_id: local={}, received={}",
                sync_state.view_id, view_id
            );
            return Ok(());
        }
        if view_id > sync_state.view_id {
            warn!(
                "⚠️ [VAULT_SEQUENCER] SELECT with higher view_id: local={}, received={}, triggering resync",
                sync_state.view_id, view_id
            );
            // TODO: Trigger view sync (PR 5)
            sync_state.view_id = view_id;
        }

        // CRITICAL: Store leader-assigned sequence (single source of truth)
        sync_state.current_sequence = sequence;
        sync_state.current_processing = Some(request_id.clone());
        drop(sync_state);

        // Verify the sender is actually the final node
        let expected_final = self.select_final_node().await?;
        if final_node_id != expected_final {
            warn!(
                "⚠️ [VAULT_SEQUENCER] SELECT from non-final node: expected={:?}, got={:?}",
                expected_final, final_node_id
            );
            return Ok(());
        }

        // Store current leader for DONE_ACK sending
        let mut current_leader = self.current_leader.write().await;
        *current_leader = Some(final_node_id);
        drop(current_leader);

        // Lock this request
        let mut locked = self.locked_request.write().await;
        *locked = Some(request_id.clone());

        // Clear wait time since we received SELECT
        let mut wait_time = self.select_wait_start_time.write().await;
        *wait_time = None;
        drop(wait_time);

        info!(
            "🔒 [VAULT_SEQUENCER] Locked request from final node: round={}, request_id={}, sequence={}, view_id={}",
            round, request_id, sequence, view_id
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
                "⚠️ [VAULT_SEQUENCER] Missing request, will fetch: {}",
                request_id
            );
            self.broadcast_missing(&request_id).await?;

            // CRITICAL: Send FETCH_REQUEST via req-resp (NOT gossip)
            // This will be handled by RPC handler
            info!(
                "📥 [VAULT_SEQUENCER] Triggering FETCH_REQUEST for missing request: {}",
                request_id
            );
            // Note: Actual fetch will be handled by RPC handler when it receives the request
            // For now, we still wait (will be replaced by fetch logic in RPC handler)
            self.wait_for_request(&request_id, round).await?;
        }

        Ok(())
    }

    /// Queue a missing transaction using its intent_hash
    /// Note: This is a placeholder - in practice, nodes should receive transaction via TransactionIdBroadcast
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
                // Note: sync_state is dropped here, we don't need it anymore
            } else {
                // Re-acquire sync_state for the warning message
                let sync_state = self.sync_state.read().await;
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

                        // Request already stored in completed_requests_cache when mark_completed was called
                        // Just clear the cached request now
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

                        // Notify waiters that the queue can advance
                        self.work_notify.notify_waiters();

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
            if let Err(e) = sequencer_clone
                .wait_for_missing_request_and_reagree(transaction_id, sequence)
                .await
            {
                warn!("⚠️ [SEQUENCER] Error waiting for missing request: {}", e);
            }
        });
    }

    /// Wait for a missing request to arrive and then agree to the proposal
    async fn wait_for_missing_request_and_reagree(
        &self,
        transaction_id: String,
        sequence: u64,
    ) -> Result<()> {
        let timeout_ms = 5000; // 5 seconds timeout
        let check_interval_ms = 100; // Check every 100ms

        let start = std::time::Instant::now();

        while start.elapsed().as_millis() < timeout_ms as u128 {
            // Check if request has arrived
            let request_exists = {
                let pending = self.pending_requests.read().await;
                pending.contains_key(&transaction_id)
            };

            if request_exists {
                // Request arrived! Now we can agree
                let mut sync_state = self.sync_state.write().await;

                // Only proceed if we're still waiting for this request and nothing else is processing
                if sync_state.missing_requests.contains(&transaction_id)
                    && sync_state.current_processing.is_none()
                {
                    // Remove from missing_requests
                    sync_state.missing_requests.remove(&transaction_id);

                    // Remove from pending_requests (safe: we just checked it exists)
                    let mut pending = self.pending_requests.write().await;
                    let request = pending.remove(&transaction_id).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Request {} disappeared from queue (race condition)",
                            transaction_id
                        )
                    })?;
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

                    return Ok(());
                } else {
                    // State changed - we're no longer waiting or something else is processing
                    info!(
                        "ℹ️ [SEQUENCER] [SYNC] Request {} arrived but state changed (current_processing: {:?})",
                        transaction_id, sync_state.current_processing
                    );
                    sync_state.missing_requests.remove(&transaction_id);
                    return Ok(());
                }
            }

            // Check if transaction has already been completed or is no longer in missing_requests
            let sync_state_check = self.sync_state.read().await;
            if !sync_state_check.missing_requests.contains(&transaction_id) {
                // Transaction is no longer in missing_requests - it was already processed
                drop(sync_state_check);
                info!(
                    "ℹ️ [SEQUENCER] [SYNC] Request {} (sequence {}) was already processed, stopping wait",
                    transaction_id, sequence
                );
                return Ok(());
            }

            // Check if this transaction has been completed (is current_processing and confirmed)
            if sync_state_check.current_processing.as_ref() == Some(&transaction_id)
                && sync_state_check.is_confirmed
            {
                // Transaction completed while we were waiting
                drop(sync_state_check);
                info!(
                    "ℹ️ [SEQUENCER] [SYNC] Request {} (sequence {}) completed while waiting, stopping wait",
                    transaction_id, sequence
                );
                return Ok(());
            }
            drop(sync_state_check);

            // Wait a bit before checking again
            tokio::time::sleep(tokio::time::Duration::from_millis(check_interval_ms)).await;
        }

        // Timeout - check one more time if transaction was completed
        let sync_state_final = self.sync_state.read().await;
        if !sync_state_final.missing_requests.contains(&transaction_id) {
            // Transaction was processed during the timeout period
            drop(sync_state_final);
            info!(
                "ℹ️ [SEQUENCER] [SYNC] Request {} (sequence {}) was processed during timeout period",
                transaction_id, sequence
            );
            return Ok(());
        }

        // Check if transaction completed
        if sync_state_final.current_processing.as_ref() == Some(&transaction_id)
            && sync_state_final.is_confirmed
        {
            drop(sync_state_final);
            info!(
                "ℹ️ [SEQUENCER] [SYNC] Request {} (sequence {}) completed during timeout period",
                transaction_id, sequence
            );
            return Ok(());
        }
        drop(sync_state_final);

        // Timeout - request never arrived
        warn!(
            "⏱️ [SEQUENCER] [SYNC] Timeout waiting for request {} (sequence {}), removing from missing_requests",
            transaction_id, sequence
        );
        let mut sync_state = self.sync_state.write().await;
        sync_state.missing_requests.remove(&transaction_id);
        Ok(())
    }

    /// Cache the request for the current processing transaction
    /// This is called when we propose a transaction and have the request object
    pub async fn cache_current_request(&self, request: ContractTransactionRequest) {
        let mut cache = self.current_request_cache.write().await;
        *cache = Some(request);
        info!("💾 [SEQUENCER] Cached request for current processing transaction");
    }

    /// Wait for a notification that new work is available or the queue state changed
    pub async fn wait_for_work(&self) {
        self.work_notify.notified().await;
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
            if let Some(ref tx_id) = sync_state.current_processing {
                info!(
                "✅ [SEQUENCER] [CONSENSUS] Consensus reached for tx_id={}: {}/{} nodes agreed (threshold: {})",
                    tx_id,
                agreed_count,
                sync_state.total_nodes,
                threshold
            );
            }
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

    /// Mark transaction as completed and send DONE_ACK to leader
    /// NOTE: State is cleared when COMMIT_CERT is received (quorum-based, not all nodes)
    pub async fn mark_completed(&self, transaction_id: &str) -> Result<()> {
        use crate::types::p2p::SerializablePeerId;
        
        // Clear exclusions for completed request
        self.clear_request_exclusions(transaction_id).await;
        
        let (sequence, view_id, round, leader_peer_id) = {
            let sync_state = self.sync_state.read().await;
            
            if sync_state.current_processing.as_deref() != Some(transaction_id) {
                warn!(
                    "⚠️ [SEQUENCER] [COMPLETE] Tried to mark tx_id={} as completed but current_processing={:?}",
                    transaction_id, sync_state.current_processing
                );
                return Ok(());
            }

            let seq = sync_state.current_sequence;
            let vid = sync_state.view_id;
            let rnd = *self.vault_sequencer_round.read().await;
            
            // Get current leader
            let leader = self.current_leader.read().await.clone();
            drop(sync_state);
            
            if let Some(leader_id) = leader {
                (seq, vid, rnd, leader_id)
            } else {
                // Fallback: try to get leader from select_final_node
                match self.select_final_node().await {
                    Ok(leader_id) => (seq, vid, rnd, leader_id),
                    Err(e) => {
                        warn!(
                            "⚠️ [SEQUENCER] [COMPLETE] Cannot determine leader for DONE_ACK: {}",
                            e
                        );
                        return Ok(());
                    }
                }
            }
        };

        let local_peer_id = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        info!(
            "✅ [SEQUENCER] [COMPLETE] Marked tx_id={} as completed locally (sequence={}, view_id={}, round={})",
            transaction_id, sequence, view_id, round
        );

        // CRITICAL: Send unicast DONE_ACK to leader via req-resp (NOT broadcast)
        if let Some(message_tx) = &self.message_tx {
            let done_ack_request = crate::types::rpc::RPCRequest::DoneAck {
                request_id: transaction_id.to_string(),
                sequence,
                view_id,
                node_id: SerializablePeerId(local_peer_id),
                round,
                sequencer_type: "vault".to_string(),
            };

            message_tx
                .send(crate::types::ChannelMessage::SendRpcRequest {
                    target_peer_id: leader_peer_id,
                    request: done_ack_request.clone(),
                })
                .await?;

            info!(
                seq_no = sequence,
                request_id = %transaction_id,
                view_id = view_id,
                round = round,
                leader_id = ?leader_peer_id,
                peer_id = ?local_peer_id,
                stage = "done_ack_sent",
                "📤 [SEQUENCER] [COMPLETE] Sent DONE_ACK to leader {:?} for tx_id={}, sequence={}",
                leader_peer_id, transaction_id, sequence
            );
            
            // Track for resend until COMMIT_CERT received
            let mut pending = self.pending_done_acks.write().await;
            pending.insert(
                (sequence, transaction_id.to_string()),
                (round, view_id, leader_peer_id, std::time::SystemTime::now()),
            );
            drop(pending);
            
            // Spawn resend task
            let sequencer_clone = self.clone();
            let message_tx_clone = message_tx.clone();
            let request_id_clone = transaction_id.to_string();
            let local_peer_id_clone = local_peer_id;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
                loop {
                    interval.tick().await;
                    
                    // Check if still pending
                    let pending_read = sequencer_clone.pending_done_acks.read().await;
                    let should_resend = pending_read.contains_key(&(sequence, request_id_clone.clone()));
                    drop(pending_read);
                    
                    if !should_resend {
                        // COMMIT_CERT received, stop resending
                        break;
                    }
                    
                    // Resend DONE_ACK
                    let pending_read = sequencer_clone.pending_done_acks.read().await;
                    if let Some((rnd, vid, leader, _)) = pending_read.get(&(sequence, request_id_clone.clone())) {
                        let resend_request = crate::types::rpc::RPCRequest::DoneAck {
                            request_id: request_id_clone.clone(),
                            sequence,
                            view_id: *vid,
                            node_id: SerializablePeerId(local_peer_id_clone),
                            round: *rnd,
                            sequencer_type: "vault".to_string(),
                        };
                        
                        if let Err(e) = message_tx_clone
                            .send(crate::types::ChannelMessage::SendRpcRequest {
                                target_peer_id: *leader,
                                request: resend_request,
                            })
                            .await
                        {
                            warn!("⚠️ [SEQUENCER] Failed to resend DONE_ACK: {}", e);
                        } else {
                            info!(
                                "🔄 [SEQUENCER] Resent DONE_ACK for tx_id={}, sequence={}",
                                request_id_clone, sequence
                            );
                        }
                    }
                }
            });
        }

            // CRITICAL: Store request in completed_requests_cache immediately after marking as completed
            // This ensures the request is available for retry even if broadcast fails 5-7 seconds later
            // We store it here (not waiting for all nodes to confirm) so it's always available for retry
            {
                info!(
                    "🔍 [SEQUENCER] [COMPLETE] Attempting to store request {} in retry cache",
                    transaction_id
                );

                // Try to get request from current_request_cache first
                let request_opt = {
                    let cache = self.current_request_cache.read().await;
                    if let Some(ref request) = *cache {
                        info!(
                            "🔍 [SEQUENCER] [COMPLETE] Found request in current_request_cache: tx_id={}, matches={}",
                            request.transaction_id,
                            request.transaction_id == transaction_id
                        );
                        if request.transaction_id == transaction_id {
                            Some(request.clone())
                        } else {
                            warn!(
                                "⚠️ [SEQUENCER] [COMPLETE] current_request_cache has different transaction_id: expected={}, found={}",
                                transaction_id,
                                request.transaction_id
                            );
                            None
                        }
                    } else {
                        info!(
                            "🔍 [SEQUENCER] [COMPLETE] current_request_cache is None for tx_id={}",
                            transaction_id
                        );
                        None
                    }
                };

                // If not in current_request_cache, try pending_requests (should still be there when mark_completed is called)
                let request_opt = if request_opt.is_none() {
                    info!(
                        "🔍 [SEQUENCER] [COMPLETE] Checking pending_requests for tx_id={}",
                        transaction_id
                    );
                    let pending = self.pending_requests.read().await;
                    let found = pending.contains_key(transaction_id);
                    info!(
                        "🔍 [SEQUENCER] [COMPLETE] pending_requests contains tx_id={}: {} (total pending: {})",
                        transaction_id,
                        found,
                        pending.len()
                    );
                    pending.get(transaction_id).cloned()
                } else {
                    info!(
                        "🔍 [SEQUENCER] [COMPLETE] Using request from current_request_cache for tx_id={}",
                        transaction_id
                    );
                    request_opt
                };

                // Store in completed_requests_cache if we found it
                if let Some(request) = request_opt {
                    let mut completed_cache = self.completed_requests_cache.write().await;
                    let was_present = completed_cache.contains_key(transaction_id);
                    completed_cache.insert(transaction_id.to_string(), request.clone());
                    info!(
                        "💾 [SEQUENCER] [COMPLETE] Stored request {} in retry cache (available for retry if broadcast fails) - was_present={}, cache_size={}",
                        transaction_id,
                        was_present,
                        completed_cache.len()
                    );
                    // Keep only last 100 completed requests to prevent unbounded growth
                    if completed_cache.len() > 100 {
                        let oldest_key = completed_cache.keys().next().cloned();
                        if let Some(key) = oldest_key {
                            completed_cache.remove(&key);
                            info!("🗑️ [SEQUENCER] Removed oldest completed request from retry cache: {}", key);
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [SEQUENCER] [COMPLETE] Could not store request {} in retry cache - not found in current_request_cache or pending_requests. This will prevent retry if transaction fails later.",
                        transaction_id
                    );
                }
            }

        // NOTE: State clearing is now done in handle_commit_cert() when COMMIT_CERT is received
        // We no longer wait for "all nodes confirmed" - quorum-based commit replaces this
        info!(
            "⏳ [SEQUENCER] [COMPLETE] DONE_ACK sent, waiting for COMMIT_CERT from leader for tx_id={}, sequence={}",
            transaction_id, sequence
        );

        Ok(())
    }

    /// Handle COMMIT_CERT message (follower-side: verify and advance state)
    pub async fn handle_commit_cert(
        &self,
        request_id: String,
        sequence: u64,
        view_id: u64,
        round: u64,
        final_node_id: libp2p::PeerId,
        acks: Vec<libp2p::PeerId>,
        quorum_size: usize,
        total_nodes: usize,
    ) -> Result<()> {
        // Verify view_id matches
        let sync_state = self.sync_state.read().await;
        let current_view_id = sync_state.view_id;
        let current_processing = sync_state.current_processing.clone();
        let current_sequence = sync_state.current_sequence;
        let last_committed = sync_state.last_committed_sequence;
        drop(sync_state);

        if view_id < current_view_id {
            warn!(
                "⚠️ [VAULT_SEQUENCER] COMMIT_CERT with stale view_id: local={}, received={}, ignoring",
                current_view_id, view_id
            );
            return Ok(());
        }

        // Verify sequence is monotonic (must be > last_committed)
        if sequence <= last_committed {
            warn!(
                "⚠️ [VAULT_SEQUENCER] COMMIT_CERT with non-monotonic sequence: last_committed={}, received={}, ignoring",
                last_committed, sequence
            );
            return Ok(());
        }

        // Verify this COMMIT_CERT is for the current processing transaction
        if current_processing.as_deref() != Some(&request_id) {
            warn!(
                "⚠️ [VAULT_SEQUENCER] COMMIT_CERT for different request: current={:?}, received={}, ignoring",
                current_processing, request_id
            );
            return Ok(());
        }

        // Verify quorum threshold
        let quorum_threshold = Self::compute_quorum_threshold(total_nodes);
        if quorum_size < quorum_threshold {
            warn!(
                "⚠️ [VAULT_SEQUENCER] COMMIT_CERT with insufficient quorum: received={}, required={}, ignoring",
                quorum_size, quorum_threshold
            );
            return Ok(());
        }

        // Verify all acks are unique
        let unique_acks: std::collections::HashSet<_> = acks.iter().collect();
        if unique_acks.len() != acks.len() {
            warn!(
                "⚠️ [VAULT_SEQUENCER] COMMIT_CERT with duplicate acks, ignoring"
            );
            return Ok(());
        }

        // Verify final_node_id matches expected leader
        let expected_leader = self.select_final_node().await?;
        if final_node_id != expected_leader {
            warn!(
                "⚠️ [VAULT_SEQUENCER] COMMIT_CERT from non-leader: expected={:?}, got={:?}, ignoring",
                expected_leader, final_node_id
            );
            return Ok(());
        }

        info!(
            seq_no = sequence,
            request_id = %request_id,
            view_id = view_id,
            round = round,
            leader_id = ?final_node_id,
            quorum_size = quorum_size,
            total_nodes = total_nodes,
            stage = "commit_cert_received",
            "✅ [VAULT_SEQUENCER] Valid COMMIT_CERT received: request_id={}, sequence={}, quorum={}/{}",
            request_id, sequence, quorum_size, total_nodes
        );

        // CRITICAL: Clear state and advance (replaces "all nodes confirmed" logic)
        let mut sync_state = self.sync_state.write().await;
        sync_state.last_committed_sequence = sequence;
        sync_state.current_processing = None;
        sync_state.agreed_nodes.clear();
        sync_state.confirmed_nodes.clear();
        sync_state.is_confirmed = false;
        
        // Mark as processed for idempotency
        sync_state.processed.insert((sequence, request_id.clone()));
        drop(sync_state);

        // Clear the cached request
        let mut cache = self.current_request_cache.write().await;
        *cache = None;
        drop(cache);

        // Clear current leader
        let mut current_leader = self.current_leader.write().await;
        *current_leader = None;
        drop(current_leader);

        // Advance round and clear selection state
        let mut round_lock = self.vault_sequencer_round.write().await;
        let old_round = *round_lock;
        *round_lock += 1;
        let new_round = *round_lock;
        drop(round_lock);

        let mut locked = self.locked_request.write().await;
        *locked = None;
        drop(locked);

        let mut cache = self.final_node_cache.write().await;
        cache.remove(&old_round);
        drop(cache);

        // Clear done_acks for this round
        let mut done_acks = self.done_acks.write().await;
        done_acks.remove(&(old_round, request_id.clone()));
        drop(done_acks);

        // Clear pending DONE_ACK resend (COMMIT_CERT received, stop resending)
        let mut pending_done_acks = self.pending_done_acks.write().await;
        pending_done_acks.remove(&(sequence, request_id.clone()));
        drop(pending_done_acks);

        // Notify waiters that the queue can advance
        self.work_notify.notify_waiters();

        info!(
            "🎉 [VAULT_SEQUENCER] COMMIT_CERT applied! State cleared, ready for next transaction (round {} -> {}, sequence {} committed)",
            old_round, new_round, sequence
        );

        Ok(())
    }

    /// Force-clear current processing state so the queue can advance after errors
    pub async fn force_clear_processing(&self, transaction_id: &str, reason: &str) {
        let mut sync_state = self.sync_state.write().await;

        if sync_state.current_processing.is_some()
            && sync_state.current_processing.as_deref() != Some(transaction_id)
        {
            warn!(
                "⚠️ [SEQUENCER] [RECOVERY] Requested clear for tx_id={} but currently processing {:?}",
                transaction_id, sync_state.current_processing
            );
        }

        if let Some(current_tx) = sync_state.current_processing.take() {
            let sequence = sync_state.current_sequence;
            sync_state.agreed_nodes.clear();
            sync_state.confirmed_nodes.clear();
            sync_state.is_confirmed = false;
            drop(sync_state);

            {
                let mut cache = self.current_request_cache.write().await;
                *cache = None;
            }

            // Advance vault round and clear any stale selection data to unblock the next dequeue
            let mut round_lock = self.vault_sequencer_round.write().await;
            let old_round = *round_lock;
            *round_lock += 1;
            let new_round = *round_lock;
            drop(round_lock);

            let mut locked = self.locked_request.write().await;
            *locked = None;
            drop(locked);

            let mut cache = self.final_node_cache.write().await;
            cache.remove(&old_round);

            warn!(
                "🧹 [SEQUENCER] [RECOVERY] Cleared processing state for tx_id={} (seq={}, round {}->{}). Reason: {}",
                current_tx, sequence, old_round, new_round, reason
            );

            // Notify waiters that the queue state changed and can be retried
            self.work_notify.notify_waiters();
        } else {
            warn!(
                "⚠️ [SEQUENCER] [RECOVERY] No current processing transaction to clear (requested for tx_id={}, reason={})",
                transaction_id, reason
            );
        }
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
    /// Sequence number for the current processing transaction (leader-assigned from SELECT)
    current_sequence: u64,
    /// Global sequence counter for deterministic ordering (leader uses this to assign sequence in SELECT)
    global_sequence: u64,
    /// Last committed sequence number (monotonic, advances only on COMMIT_CERT)
    last_committed_sequence: u64,
    /// Current view ID (membership epoch, increments on membership change)
    view_id: u64,
    /// Nodes that have agreed to process the current request
    agreed_nodes: HashSet<String>,
    /// Nodes that have confirmed completion of the current request
    confirmed_nodes: HashSet<String>,
    /// Total number of active nodes (for consensus threshold)
    total_nodes: usize,
    /// Whether current transaction is confirmed (all nodes confirmed) - DEPRECATED: use COMMIT_CERT instead
    is_confirmed: bool,
    /// Processed transactions for idempotency: (round, request_id)
    processed: HashSet<(u64, String)>,
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
    /// Notify waiting tasks when queue state changes
    work_notify: Arc<Notify>,

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
    /// Tracks rounds for which THIS node has performed VRF selection
    /// This prevents skipping VRF when consensus results arrive from other nodes first
    main_vrf_performed_rounds: Arc<RwLock<HashSet<u64>>>,
    /// Per-request exclusion list: tracks peers that have timed out repeatedly
    /// Format: request_id -> set of excluded peer_ids
    peer_exclusions: Arc<RwLock<HashMap<String, HashSet<libp2p::PeerId>>>>,
    /// Per-peer timeout counts: tracks how many times each peer has timed out per request
    /// Format: (request_id, peer_id) -> timeout_count
    peer_timeout_counts: Arc<RwLock<HashMap<(String, libp2p::PeerId), u32>>>,
    /// DONE_ACK collection: tracks acks received for (round, request_id)
    /// Format: (round, request_id) -> HashSet<PeerId>
    done_acks: Arc<RwLock<HashMap<(u64, String), HashSet<libp2p::PeerId>>>>,
    /// Current leader (final_node_id) for the current processing transaction
    current_leader: Arc<RwLock<Option<libp2p::PeerId>>>,
    /// Pending DONE_ACKs that need resending: (sequence, request_id) -> (round, view_id, leader_peer_id, last_sent)
    /// Resend every 2s until COMMIT_CERT received
    pending_done_acks: Arc<RwLock<HashMap<(u64, String), (u64, u64, libp2p::PeerId, std::time::SystemTime)>>>,
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
                last_committed_sequence: 0,
                view_id: 0,
                agreed_nodes: HashSet::new(),
                confirmed_nodes: HashSet::new(),
                total_nodes: 0,
                is_confirmed: false,
                processed: HashSet::new(),
            })),
            message_tx: None,
            node_id: String::new(),
            current_request_cache: Arc::new(RwLock::new(None)),
            work_notify: Arc::new(Notify::new()),

            // Initialize VRF + Consensus fields
            local_peer_id: None,
            main_sequencer_round: Arc::new(RwLock::new(0)),
            vrf_service: None,
            consensus_node: None,
            available_nodes: Arc::new(RwLock::new(Vec::new())),
            final_node_cache: Arc::new(RwLock::new(HashMap::new())),
            locked_request: Arc::new(RwLock::new(None)),
            main_vrf_performed_rounds: Arc::new(RwLock::new(HashSet::new())),
            peer_exclusions: Arc::new(RwLock::new(HashMap::new())),
            peer_timeout_counts: Arc::new(RwLock::new(HashMap::new())),
            done_acks: Arc::new(RwLock::new(HashMap::new())),
            current_leader: Arc::new(RwLock::new(None)),
            pending_done_acks: Arc::new(RwLock::new(HashMap::new())),
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

    /// Select leader deterministically using HRW (Highest Random Weight) / Rendezvous Hashing
    /// Returns ordered list of top-N leaders for failover support
    /// 
    /// Algorithm:
    /// - score(p) = hash(request_id || round || peer_id)
    /// - leader = argmax_p score(p)
    /// - Tie-break: lexicographically smallest peer_id
    async fn select_leader_with_hrw(
        &self,
        request_id: &str,
        round: u64,
        max_candidates: usize,
    ) -> Result<Vec<libp2p::PeerId>> {
        // Get eligible candidates (exclude timed-out peers)
        let available = self.available_nodes.read().await.clone();
        let excluded = {
            let exclusions = self.peer_exclusions.read().await;
            exclusions.get(request_id).cloned().unwrap_or_default()
        };
        let candidates = get_eligible_candidates(&available, &excluded);

        if candidates.is_empty() {
            return Err(anyhow::anyhow!("No eligible candidates for HRW selection"));
        }

        // Compute HRW scores for all candidates
        let mut scored: Vec<(libp2p::PeerId, [u8; 32])> = candidates
            .iter()
            .map(|peer_id| {
                let score = compute_hrw_score(request_id, round, peer_id);
                (*peer_id, score)
            })
            .collect();

        // Sort by score (descending), then by peer_id (ascending) for tie-break
        scored.sort_by(|a, b| {
            match b.1.cmp(&a.1) {
                // Descending by score
                std::cmp::Ordering::Equal => {
                    // Tie-break: lexicographically smallest peer_id
                    a.0.to_bytes().cmp(&b.0.to_bytes())
                }
                other => other,
            }
        });

        // Return top-N leaders
        let leaders: Vec<libp2p::PeerId> = scored
            .into_iter()
            .take(max_candidates)
            .map(|(peer_id, _)| peer_id)
            .collect();

        info!(
            "🎯 [MAIN_SEQUENCER] HRW selected {} leader(s) for request_id={}, round={}: {:?}",
            leaders.len(),
            request_id,
            round,
            leaders.iter().map(|p| p.to_string()).collect::<Vec<_>>()
        );

        Ok(leaders)
    }

    /// Record a timeout for a peer on a specific request
    /// If timeout count exceeds threshold (default: 3), peer is excluded from HRW selection
    pub async fn record_peer_timeout(&self, request_id: &str, peer_id: libp2p::PeerId, timeout_threshold: u32) {
        let mut timeout_counts = self.peer_timeout_counts.write().await;
        let key = (request_id.to_string(), peer_id);
        let count = timeout_counts.entry(key.clone()).or_insert(0);
        *count += 1;

        if *count >= timeout_threshold {
            let mut exclusions = self.peer_exclusions.write().await;
            exclusions.entry(request_id.to_string())
                .or_insert_with(HashSet::new)
                .insert(peer_id);
            warn!(
                "⚠️ [MAIN_SEQUENCER] Peer {} excluded from HRW for request {} ({} timeouts >= threshold {})",
                peer_id, request_id, count, timeout_threshold
            );
        } else {
            info!(
                "📊 [MAIN_SEQUENCER] Peer {} timeout count for request {}: {}/{}",
                peer_id, request_id, count, timeout_threshold
            );
        }
    }

    /// Clear exclusion and timeout counts for a completed request
    pub async fn clear_request_exclusions(&self, request_id: &str) {
        let mut exclusions = self.peer_exclusions.write().await;
        exclusions.remove(request_id);
        
        let mut timeout_counts = self.peer_timeout_counts.write().await;
        timeout_counts.retain(|(req_id, _), _| req_id != request_id);
        
        info!("🧹 [MAIN_SEQUENCER] Cleared exclusions for completed request {}", request_id);
    }

    /// Compute quorum threshold using ceil(2N/3) formula
    /// CRITICAL: Uses ceil, not floor, to ensure safety
    /// Formula: max(2, (2 * total_nodes + 2) / 3)
    /// Examples:
    ///   - N=3: quorum = 2 (ceil(6/3)=2)
    ///   - N=4: quorum = 3 (ceil(8/3)=3, NOT 2)
    ///   - N=5: quorum = 4 (ceil(10/3)=4, NOT 3)
    ///   - N=7: quorum = 5 (ceil(14/3)=5, NOT 4)
    pub fn compute_quorum_threshold(total_nodes: usize) -> usize {
        if total_nodes == 0 {
            return 0;
        }
        // Integer ceil for 2N/3: (2*n + 2) / 3
        let quorum = (2 * total_nodes + 2) / 3;
        // Minimum 2 nodes for 3-node cluster
        quorum.max(2)
    }

    /// Check if this node is the final node for a given request using HRW
    pub async fn am_i_final_node_for_request(&self, request_id: &str, round: u64) -> Result<bool> {
        let local_peer = self
            .local_peer_id
            .ok_or_else(|| anyhow::anyhow!("Local peer ID not set"))?;

        // Use HRW to compute leaders
        let leaders = self.select_leader_with_hrw(request_id, round, 1).await?;
        
        if leaders.is_empty() {
            return Err(anyhow::anyhow!("No leaders computed for request_id={}", request_id));
        }

        let final_node = leaders[0];
        let is_final = local_peer == final_node;

        if is_final {
            info!(
                "✅ [MAIN_SEQUENCER] am_i_final_node_for_request() = true: local_peer={:?}, final_node={:?}, request_id={}, round={}",
                local_peer, final_node, request_id, round
            );
        } else {
            debug!(
                "🔍 [MAIN_SEQUENCER] am_i_final_node_for_request() = false: local_peer={:?}, final_node={:?}, request_id={}, round={}",
                local_peer, final_node, request_id, round
            );
        }

        Ok(is_final)
    }

    /// Select final node deterministically for current round using VRF + Consensus
    /// Returns the peer ID of the selected node (from consensus cache)
    /// 
    /// DEPRECATED: Use select_leader_with_hrw() instead
    #[allow(dead_code)]
    async fn select_final_node(&self) -> Result<libp2p::PeerId> {
        let round = *self.main_sequencer_round.read().await;

        // Check if consensus has completed for this round
        {
            let cache = self.final_node_cache.read().await;
            if let Some(final_node) = cache.get(&round) {
                return Ok(*final_node);
            }
        }

        // Fallback: use the validated consensus result from the consensus node (mirrors signing flow)
        if let Some(consensus) = &self.consensus_node {
            let consensus_guard = consensus.read().await;
            if let Some(result) = consensus_guard.get_consensus_result(round) {
                let mut cache = self.final_node_cache.write().await;
                cache.insert(round, result.final_node.0);
                return Ok(result.final_node.0);
            }
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

            // Mark this round as VRF-performed to prevent re-triggering
            self.main_vrf_performed_rounds.write().await.insert(round);
            info!(
                "🎯 [MAIN_SEQUENCER] Round {} VRF COMPLETE: This node has performed and broadcasted its VRF selection",
                round
            );
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

            // Broadcast the consensus result to other nodes
            if let Some(message_tx) = &self.message_tx {
                let consensus_msg = ConsensusMessage::FinalNodeResult {
                    result: result.clone(),
                    round,
                };

                // Wrap in GossipsubMessage::Consensus for proper deserialization
                let gossipsub_msg = GossipsubMessage::Consensus(consensus_msg);
                let broadcast_data = serde_json::to_vec(&gossipsub_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize consensus message: {}", e))?;

                message_tx
                    .send(crate::types::ChannelMessage::Broadcast {
                        topic: "consensus-result".to_string(),
                        data: broadcast_data,
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to broadcast consensus result: {}", e))?;

                info!(
                    "📤 [MAIN_SEQUENCER] Broadcasted consensus result for round {}",
                    round
                );
            } else {
                warn!("⚠️ [MAIN_SEQUENCER] No message channel available to broadcast consensus result");
            }

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

    /// Handle consensus message from another node
    pub async fn handle_consensus_message(
        &self,
        msg: crate::types::ConsensusMessage,
    ) -> Result<()> {
        // Extract round from consensus message
        let crate::types::ConsensusMessage::FinalNodeResult { round, .. } = msg;
        let final_round = Some(round);

        if let Some(consensus) = &self.consensus_node {
            let mut consensus_node = consensus.write().await;
            consensus_node.handle_message(msg).await?;
            info!("✅ [MAIN_SEQUENCER] Handled consensus message");
        } else {
            warn!("⚠️ [MAIN_SEQUENCER] Consensus node not available to handle message");
        }

        // Update the local final-node cache using the consensus result (validated or pending)
        // CRITICAL FIX: Only cache consensus for rounds where THIS MAIN SEQUENCER performed VRF
        // NOTE: We cache even pending results - they will be validated when selected_nodes arrive
        // This prevents caching signing module rounds (which use different VRF rounds)
        if let Some(round) = final_round {
            if let Some(consensus) = &self.consensus_node {
                let consensus_guard = consensus.read().await;
                if let Some(result) = consensus_guard.get_consensus_result(round) {
                    // Check if THIS main sequencer performed VRF for this round
                    let has_performed_vrf =
                        self.main_vrf_performed_rounds.read().await.contains(&round);

                    if has_performed_vrf {
                        // Cache the result (both VALIDATED and PENDING)
                        // Even PENDING results should be cached so the final node can identify itself
                        let mut cache = self.final_node_cache.write().await;
                        cache.insert(round, result.final_node.0);
                        let is_pending = consensus_guard.is_result_pending(round);
                        if is_pending {
                            info!(
                                "💾 [MAIN_SEQUENCER] Cached final node {:?} for round {} from consensus message (PENDING - will validate when VRF data arrives)",
                                result.final_node.0, round
                            );
                        } else {
                            info!(
                                "💾 [MAIN_SEQUENCER] Cached final node {:?} for round {} from consensus message (VALIDATED)",
                                result.final_node.0, round
                            );
                        }
                    } else {
                        // This round is from another module (signing/vault) - ignore it
                        debug!(
                            "🔕 [MAIN_SEQUENCER] Ignoring consensus for round {} - main sequencer never performed VRF for this round (likely from signing/vault module)",
                            round
                        );
                    }
                } else {
                    // This should rarely happen now - get_consensus_result checks both validated and pending
                    info!(
                        "⏳ [MAIN_SEQUENCER] Consensus message received for round {} but no result found (neither validated nor pending) - will retry when selected_nodes arrive",
                        round
                    );
                }
            }
        }
        Ok(())
    }

    /// Handle VRF selected nodes broadcast from another node
    pub async fn handle_vrf_broadcast(
        &self,
        broadcast: crate::protocols::VrfSelectedNodesBroadcast,
        sender_peer_id: libp2p::PeerId,
        total_nodes: usize,
    ) -> Result<()> {
        if let Some(vrf_service) = &self.vrf_service {
            vrf_service
                .handle_vrf_broadcast(broadcast, sender_peer_id, total_nodes)
                .await?;
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

        // Wake any tasks waiting for new work to arrive
        self.work_notify.notify_waiters();

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

        // Sync round first to ensure all nodes have the same round
        let round = match self.sync_round_with_peers().await {
            Ok(r) => r,
            Err(e) => {
                warn!("⚠️ [MAIN_SEQUENCER] Round sync failed: {}, using local round", e);
                *self.main_sequencer_round.read().await
            }
        };

        // Get the first request from queue to compute HRW
        let (first_tx_id, first_request) = {
            let pending = self.pending_requests.read().await;
            if let Some((tx_id, request)) = pending.first_key_value() {
                (tx_id.clone(), request.clone())
            } else {
                return None;
            }
        };

        info!(
            "📤 [MAIN_SEQUENCER] Dequeue attempt: round={}, queue_len={}, first_request={}",
            round, queue_len, first_tx_id
        );

        // Use HRW to get top-3 leaders for failover support
        let leaders = match self.select_leader_with_hrw(&first_tx_id, round, 3).await {
            Ok(leaders) => leaders,
            Err(e) => {
                error!(
                    "❌ [MAIN_SEQUENCER] Failed to compute HRW for request {}: {}",
                    first_tx_id, e
                );
                return None;
            }
        };

        if leaders.is_empty() {
            error!("❌ [MAIN_SEQUENCER] No leaders computed for request {}", first_tx_id);
            return None;
        }

        let local_peer = match self.local_peer_id {
            Some(peer) => peer,
            None => {
                error!("❌ [MAIN_SEQUENCER] Local peer ID not set");
                return None;
            }
        };

        // Check if we are the primary leader (leader[0])
        let is_primary_leader = local_peer == leaders[0];
        let leader_index = leaders.iter().position(|&p| p == local_peer);

        if is_primary_leader {
            info!(
                "✅ [MAIN_SEQUENCER] Round {}: HRW selected this node as PRIMARY leader for request {}",
                round, first_tx_id
            );
        } else if let Some(idx) = leader_index {
            info!(
                "🔍 [MAIN_SEQUENCER] Round {}: This node is backup leader #{} for request {} (primary: {:?})",
                round, idx + 1, first_tx_id, leaders[0]
            );
        } else {
            debug!(
                "🔍 [MAIN_SEQUENCER] Round {}: HRW selected another node as leader for request {} (primary: {:?})",
                round, first_tx_id, leaders[0]
            );
        }

        // Check if we are the primary leader
        if is_primary_leader {
            // We are the leader - select the request
            let mut pending = self.pending_requests.write().await;
            if let Some((tx_id, request)) = pending.pop_first() {
                let sequence = request.sequence;
                let queue_size = pending.len();
                info!(
                    "🎯 [MAIN_SEQUENCER] Leader selecting request: tx_id={}, sequence={}, remaining={}",
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
        } else {
            // We are NOT the leader - wait for SELECT message
            None
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

        // CRITICAL: Leader assigns sequence (single source of truth)
        let (sequence, view_id) = {
            let mut sync_state = self.sync_state.write().await;
            sync_state.global_sequence += 1;
            let seq = sync_state.global_sequence;
            let vid = sync_state.view_id;
            (seq, vid)
        };

        // Create signature (simplified - in production use proper signing)
        let signature = vec![]; // TODO: Sign with node's private key

        // Broadcast via message channel
        if let Some(tx) = &self.message_tx {
            let msg = crate::types::ChannelMessage::Broadcast {
                topic: "main-sequencer-select".to_string(),
                data: serde_json::to_vec(&crate::types::GossipsubMessage::MainSequencerSelect {
                    round,
                    request_id: request_id.to_string(),
                    sequence,        // CRITICAL: Leader-assigned sequence
                    view_id,         // Current view ID
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
        sequence: u64,
        view_id: u64,
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

        // Verify view_id (allow higher view_id to trigger resync)
        let mut sync_state = self.sync_state.write().await;
        if view_id < sync_state.view_id {
            warn!(
                "⚠️ [MAIN_SEQUENCER] SELECT with stale view_id: local={}, received={}",
                sync_state.view_id, view_id
            );
            return Ok(());
        }
        if view_id > sync_state.view_id {
            warn!(
                "⚠️ [MAIN_SEQUENCER] SELECT with higher view_id: local={}, received={}, triggering resync",
                sync_state.view_id, view_id
            );
            // TODO: Trigger view sync (PR 5)
            sync_state.view_id = view_id;
        }

        // CRITICAL: Store leader-assigned sequence (single source of truth)
        sync_state.current_sequence = sequence;
        sync_state.current_processing = Some(request_id.clone());
        drop(sync_state);

        // Verify the sender is actually the final node
        let expected_final = self.select_final_node().await?;
        if final_node_id != expected_final {
            warn!(
                "⚠️ [MAIN_SEQUENCER] SELECT from non-final node: expected={:?}, got={:?}",
                expected_final, final_node_id
            );
            return Ok(());
        }

        // Store current leader for DONE_ACK sending
        let mut current_leader = self.current_leader.write().await;
        *current_leader = Some(final_node_id);
        drop(current_leader);

        // Lock this request
        let mut locked = self.locked_request.write().await;
        *locked = Some(request_id.clone());

        info!(
            "🔒 [MAIN_SEQUENCER] Locked request from final node: round={}, request_id={}, sequence={}, view_id={}",
            round, request_id, sequence, view_id
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
                "⚠️ [MAIN_SEQUENCER] Missing request, will fetch: {}",
                request_id
            );
            self.broadcast_missing(&request_id).await?;

            // CRITICAL: Send FETCH_REQUEST via req-resp (NOT gossip)
            info!(
                "📥 [MAIN_SEQUENCER] Triggering FETCH_REQUEST for missing request: {}",
                request_id
            );
            // Note: Actual fetch will be handled by RPC handler when it receives the request
            // For now, we still wait (will be replaced by fetch logic in RPC handler)
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
        // Clear exclusions for completed request
        self.clear_request_exclusions(transaction_id).await;
        
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

                // Advance round and clear selection state so the next dequeue can proceed
                let mut round_lock = self.main_sequencer_round.write().await;
                let old_round = *round_lock;
                *round_lock += 1;
                let new_round = *round_lock;
                drop(round_lock);

                let mut locked = self.locked_request.write().await;
                *locked = None;
                drop(locked);

                let mut cache = self.final_node_cache.write().await;
                cache.remove(&old_round);
                drop(cache);

                // Notify waiters that the queue can advance
                self.work_notify.notify_waiters();

                info!(
                    "🎉 [NETWORK_SEQUENCER] [COMPLETE] Round advanced for tx_id={} ({} -> {}), queue ready for next request",
                    completed_tx.as_deref().unwrap_or_default(),
                    old_round,
                    new_round
                );
            }
        }

        Ok(())
    }

    /// Force-clear current processing state so the queue can advance after errors
    pub async fn force_clear_processing(&self, transaction_id: &str, reason: &str) {
        let mut sync_state = self.sync_state.write().await;

        if sync_state.current_processing.is_some()
            && sync_state.current_processing.as_deref() != Some(transaction_id)
        {
            warn!(
                "⚠️ [NETWORK_SEQUENCER] [RECOVERY] Requested clear for tx_id={} but currently processing {:?}",
                transaction_id, sync_state.current_processing
            );
        }

        if let Some(current_tx) = sync_state.current_processing.take() {
            let sequence = sync_state.current_sequence;
            sync_state.agreed_nodes.clear();
            sync_state.confirmed_nodes.clear();
            sync_state.is_confirmed = false;
            drop(sync_state);

            {
                let mut cache = self.current_request_cache.write().await;
                *cache = None;
            }

            // Advance main round and clear any stale selection data to unblock the next dequeue
            let mut round_lock = self.main_sequencer_round.write().await;
            let old_round = *round_lock;
            *round_lock += 1;
            let new_round = *round_lock;
            drop(round_lock);

            let mut locked = self.locked_request.write().await;
            *locked = None;
            drop(locked);

            let mut cache = self.final_node_cache.write().await;
            cache.remove(&old_round);

            warn!(
                "🧹 [NETWORK_SEQUENCER] [RECOVERY] Cleared processing state for tx_id={} (seq={}, round {}->{}). Reason: {}",
                current_tx, sequence, old_round, new_round, reason
            );

            // Notify waiters that the queue state changed and can be retried
            self.work_notify.notify_waiters();
        } else {
            warn!(
                "⚠️ [NETWORK_SEQUENCER] [RECOVERY] No current processing transaction to clear (requested for tx_id={}, reason={})",
                transaction_id, reason
            );
        }
    }

    /// Cache the request for the current processing transaction
    pub async fn cache_current_request(&self, request: NetworkTransactionRequest) {
        let mut cache = self.current_request_cache.write().await;
        *cache = Some(request);
        info!("💾 [NETWORK_SEQUENCER] Cached request for current processing transaction");
    }

    /// Wait for a notification that new work is available or the queue state changed
    pub async fn wait_for_work(&self) {
        self.work_notify.notified().await;
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

                        // Notify waiters that the queue can advance
                        self.work_notify.notify_waiters();

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
        // Note: "cancelled" state is only used by ContractTransactionSequencer for retry mechanism
        // NetworkTransactionSequencer doesn't have retry, so no cancellation handling needed here
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
                    amount: "10".to_string(),
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
