//! Nonce Generation Protocol for Threshold ECDSA with Random k
//!
//! This module implements distributed nonce generation using additive shares.
//! Instead of using a fixed k value, each node generates a random k_i and
//! the group computes R = Σ R_i where R_i = k_i * G.
//!
//! ## Protocol Overview
//!
//! ### Phase 1: Commitment
//! - Each node generates random k_i
//! - Computes R_i = k_i * G
//! - Broadcasts commitment H(R_i || batch_id)
//!
//! ### Phase 2: Reveal
//! - After receiving threshold commitments, reveal R_i
//! - Verify each R_i matches its commitment
//! - Compute aggregate R = Σ R_i
//!
//! ### Phase 3: Inversion (for k⁻¹ shares)
//! - Use MtA (Multiplicative-to-Additive) protocol to compute shares of k⁻¹
//! - Or use pre-computed Beaver triples
//!
//! ### Storage
//! - Store (k_i, k_inv_i, R, r) tuples for later signing
//! - Each tuple is single-use (consumed after signing)

pub mod generation;
pub mod handlers;

use crate::database::storage::NonceStorage;
use crate::types::nonce::{NonceGenState, NonceGenStatus, NoncePoolConfig, NonceTuple};
use crate::types::secp::{SerializablePoint, SerializableScalar};
use crate::types::signing::SigningMessage;
use crate::types::ChannelMessage;
use anyhow::Result;
use ff::PrimeField;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, U256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{error, info, warn};

pub use generation::NonceGenerator;

/// A pending nonce request waiting for a nonce to become available
struct PendingNonceRequest {
    /// Channel to send the nonce back to the requester
    response_tx: oneshot::Sender<NonceTuple>,
    /// Request ID for logging
    request_id: u64,
    /// Timestamp when request was queued
    queued_at: std::time::Instant,
}

/// Manager for the nonce pool and generation protocol
pub struct NonceManager {
    /// Node ID
    id: String,

    /// Threshold for signing (t-of-n)
    threshold: usize,

    /// Total number of nodes (updated dynamically when nodes join/leave)
    total_nodes: AtomicUsize,

    /// Number of DKG signers (nodes that hold DKG key shares for signing).
    /// Only DKG signers participate in nonce commit-reveal generation;
    /// observer nodes receive finalized nonces via NonceTupleBroadcast.
    /// The stale-nonce filter compares num_contributors against this value
    /// to ensure nonces were created with all DKG signers participating.
    dkg_signer_count: AtomicUsize,

    /// Storage backend
    storage: NonceStorage,

    /// Channel for sending messages
    message_tx: mpsc::Sender<ChannelMessage>,

    /// Active nonce generation batches
    active_batches: Arc<RwLock<HashMap<String, NonceGenState>>>,

    /// Pool configuration
    config: NoncePoolConfig,

    /// Nonce generator for protocol execution (uses interior mutability)
    generator: std::sync::Mutex<NonceGenerator>,

    /// Queue of pending nonce requests waiting for nonces
    pending_requests: Arc<RwLock<Vec<PendingNonceRequest>>>,

    /// Counter for generating unique request IDs
    request_counter: AtomicU64,

    /// Flag indicating if startup pre-generation is complete
    startup_ready: Arc<AtomicBool>,

    /// Flag indicating if a generation batch is currently in progress
    generation_in_progress: Arc<AtomicBool>,

    /// Whether this node is a DKG signer (holds a DKG secret share).
    /// Only DKG signers can initiate or join the commit-reveal nonce
    /// generation protocol.  Observer nodes receive finalized nonces
    /// passively via NonceTupleBroadcast and must NOT call
    /// start_generation / join_generation / maybe_trigger_generation.
    is_dkg_signer: AtomicBool,
}

impl NonceManager {
    /// Create a new NonceManager
    ///
    /// `dkg_signer_count`: number of initial DKG signers that participate in nonce
    /// generation.  On DKG nodes this equals `total_nodes` at genesis; on observer
    /// nodes it is the signer count received from the PeerList RPC.  The stale-nonce
    /// filter compares `num_contributors` against this value (not `total_nodes`).
    pub fn new(
        id: String,
        threshold: usize,
        total_nodes: usize,
        dkg_signer_count: usize,
        storage: NonceStorage,
        message_tx: mpsc::Sender<ChannelMessage>,
        config: NoncePoolConfig,
    ) -> Self {
        let generator = NonceGenerator::new(id.clone(), threshold);

        Self {
            id,
            threshold,
            total_nodes: AtomicUsize::new(total_nodes),
            dkg_signer_count: AtomicUsize::new(dkg_signer_count),
            storage,
            message_tx,
            active_batches: Arc::new(RwLock::new(HashMap::new())),
            config,
            generator: std::sync::Mutex::new(generator),
            pending_requests: Arc::new(RwLock::new(Vec::new())),
            request_counter: AtomicU64::new(0),
            startup_ready: Arc::new(AtomicBool::new(false)),
            generation_in_progress: Arc::new(AtomicBool::new(false)),
            is_dkg_signer: AtomicBool::new(false),
        }
    }

    /// Mark this node as a DKG signer (holds a DKG secret share).
    /// Must be called after DKG completion or on restart when a share is found
    /// in storage.  Until this is set, nonce generation is suppressed.
    pub fn set_is_dkg_signer(&self, value: bool) {
        self.is_dkg_signer.store(value, Ordering::SeqCst);
        info!("🔑 [NONCE] is_dkg_signer set to {}", value);
    }

    /// Check if this node is a DKG signer.
    pub fn is_dkg_signer(&self) -> bool {
        self.is_dkg_signer.load(Ordering::SeqCst)
    }

    /// Check if startup pre-generation is complete
    pub fn is_startup_ready(&self) -> bool {
        self.startup_ready.load(Ordering::SeqCst)
    }

    /// Mark startup pre-generation as complete
    pub fn set_startup_ready(&self) {
        self.startup_ready.store(true, Ordering::SeqCst);
        info!("✅ [NONCE] Startup pre-generation complete, ready to accept signing requests");
    }

    /// Update the total number of nodes.
    ///
    /// Call this when nodes join or leave the network.
    /// NOTE: Stale-nonce filtering uses `dkg_signer_count`, not `total_nodes`.
    /// `total_nodes` is still tracked for nonce generation protocol peer counting.
    pub fn update_total_nodes(&self, new_total: usize) {
        let old_total = self.total_nodes.swap(new_total, Ordering::SeqCst);
        if old_total != new_total {
            info!(
                "📊 [NONCE] Updated total_nodes: {} -> {} (stale filter still uses dkg_signer_count={})",
                old_total, new_total, self.dkg_signer_count.load(Ordering::SeqCst)
            );
        }
    }

    /// Update the DKG signer count used for stale-nonce filtering.
    ///
    /// This should only change during a DKG refresh/reshare (extremely rare).
    /// Observer nodes set this from the `dkg_signer_count` received via PeerList RPC.
    pub fn update_dkg_signer_count(&self, count: usize) {
        let old = self.dkg_signer_count.swap(count, Ordering::SeqCst);
        if old != count {
            info!(
                "📊 [NONCE] Updated dkg_signer_count: {} -> {} (nonces with <{} contributors are now stale)",
                old, count, count
            );
        }
    }

    /// Get the current DKG signer count (number of nodes participating in nonce generation).
    pub fn get_dkg_signer_count(&self) -> usize {
        self.dkg_signer_count.load(Ordering::SeqCst)
    }

    /// Handle a new node joining the network.
    ///
    /// When a new node joins:
    /// 1. Update total_nodes count
    /// 2. DELETE all existing nonces (they're stale - new node doesn't have them)
    /// 3. Trigger immediate nonce regeneration with all nodes
    ///
    /// This ensures all nodes have the same nonces in their database.
    /// Without this, the new node would fail to sign because it doesn't have
    /// the pre-generated nonces that other nodes have.
    pub async fn handle_node_joined(&self, new_total: usize) -> Result<()> {
        let old_total = self.total_nodes.swap(new_total, Ordering::SeqCst);

        if new_total <= old_total {
            // Node count decreased or stayed same - no need to regenerate
            return Ok(());
        }

        let current_dkg_count = self.dkg_signer_count.load(Ordering::SeqCst);

        info!(
            "🔄🔄🔄 [NONCE] NEW NODE JOINED! total_nodes: {} -> {}, dkg_signer_count={} 🔄🔄🔄",
            old_total, new_total, current_dkg_count
        );

        // Use dkg_signer_count (not new_total) for stale-nonce deletion.
        // Observer nodes don't participate in nonce generation, so their count
        // should NOT affect which nonces are considered stale.
        // Nonces are stale only if created with fewer DKG signers than current.
        let deleted = self.storage.delete_stale_nonces(current_dkg_count).await?;

        if deleted > 0 {
            info!(
                "🗑️ [NONCE] Deleted {} stale nonces (num_contributors < dkg_signer_count={})",
                deleted, current_dkg_count
            );
        }

        // Step 2: Cancel any in-progress generation (it won't include new node)
        {
            let mut batches = self.active_batches.write().await;
            if !batches.is_empty() {
                info!(
                    "⏹️ [NONCE] Cancelling {} in-progress batches (need to restart with new node)",
                    batches.len()
                );
                batches.clear();
            }
        }
        self.generation_in_progress.store(false, Ordering::SeqCst);

        // Step 3: Trigger immediate nonce regeneration with all nodes
        info!(
            "🚀 [NONCE] Triggering immediate nonce regeneration with {} nodes",
            new_total
        );

        let round = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.generation_in_progress.store(true, Ordering::SeqCst);
        if let Err(e) = self.start_generation(round).await {
            warn!("⚠️ [NONCE] Failed to start regeneration after node join: {}", e);
            self.generation_in_progress.store(false, Ordering::SeqCst);
        }

        Ok(())
    }

    /// Flush the entire nonce pool and cancel any in-progress generation.
    ///
    /// Called when a main DKG node restarts after being offline. Because the node
    /// may have missed NonceInvalidation messages while down, we cannot trust any
    /// of the old nonces. The node will request a fresh pool from a connected peer
    /// via RequestNoncePoolSync after this call.
    pub async fn flush_all_nonces(&self) -> Result<usize> {
        // Cancel any in-progress generation batches
        {
            let mut batches = self.active_batches.write().await;
            if !batches.is_empty() {
                info!(
                    "⏹️ [NONCE] Cancelling {} in-progress batches during flush",
                    batches.len()
                );
                batches.clear();
            }
        }
        self.generation_in_progress.store(false, Ordering::SeqCst);

        // Delete all nonce tuples from storage
        let deleted = self.storage.delete_all_nonces().await?;

        info!(
            "🗑️ [NONCE] Flushed entire nonce pool ({} nonces) - will sync from peer",
            deleted
        );

        Ok(deleted)
    }

    /// Get the current total number of nodes
    pub fn get_total_nodes(&self) -> usize {
        self.total_nodes.load(Ordering::SeqCst)
    }

    /// Request a nonce, waiting in queue if none available.
    ///
    /// This method:
    /// 1. First tries to get an available nonce from the pool
    /// 2. If none available, queues the request and waits
    /// 3. Triggers generation if needed
    /// 4. Returns when a nonce becomes available
    ///
    /// This is the preferred method for signing operations as it never fails
    /// due to empty pool - it will wait for nonces to be generated.
    pub async fn request_nonce(&self) -> Result<NonceTuple> {
        let min_contributors = self.dkg_signer_count.load(Ordering::SeqCst);

        // First, try to get an existing valid nonce (filtering out stale ones)
        let max_to_check = 1000; // Check up to 1000 nonces to find a valid one
        let available = self.storage.get_available_tuples(max_to_check).await?;

        for tuple in available {
            // Skip stale nonces (created with fewer DKG signers than current count)
            let valid = tuple.num_contributors > 0 && tuple.num_contributors >= min_contributors;
            if !valid {
                continue;
            }

            self.storage.consume_nonce_tuple(&tuple.tuple_id).await?;
            self.storage.record_consumption().await?;

            info!(
                "🔐 [NONCE] Acquired nonce immediately: {} (contributors: {}, pool size: {})",
                tuple.tuple_id,
                tuple.num_contributors,
                self.storage.available_nonce_count().await?
            );

            // Check if we need to trigger background refill
            self.maybe_trigger_generation().await;

            return Ok(tuple);
        }

        // No nonces available - queue the request
        let request_id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        info!(
            "⏳ [NONCE] No nonces available, queuing request #{} and triggering generation",
            request_id
        );

        // Add to pending queue
        {
            let mut pending = self.pending_requests.write().await;
            pending.push(PendingNonceRequest {
                response_tx: tx,
                request_id,
                queued_at: std::time::Instant::now(),
            });
            info!(
                "📋 [NONCE] Request #{} queued (queue size: {})",
                request_id, pending.len()
            );
        }

        // Trigger generation if not already in progress
        self.maybe_trigger_generation().await;

        // Wait for nonce with timeout
        let timeout = std::time::Duration::from_millis(self.config.phase_timeout_ms * 5);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(nonce)) => {
                info!(
                    "🔐 [NONCE] Request #{} fulfilled with nonce {}",
                    request_id, nonce.tuple_id
                );
                Ok(nonce)
            }
            Ok(Err(_)) => {
                error!("❌ [NONCE] Request #{} channel closed unexpectedly", request_id);
                Err(anyhow::anyhow!("Nonce request channel closed"))
            }
            Err(_) => {
                error!(
                    "❌ [NONCE] Request #{} timed out after {}ms",
                    request_id, timeout.as_millis()
                );
                // Remove from pending queue on timeout
                let mut pending = self.pending_requests.write().await;
                pending.retain(|r| r.request_id != request_id);
                Err(anyhow::anyhow!("Nonce request timed out"))
            }
        }
    }

    /// Try to fulfill pending requests from available nonces.
    /// Called after new nonces are generated or when checking pool.
    pub async fn fulfill_pending_requests(&self) -> Result<usize> {
        let mut fulfilled = 0;
        let min_contributors = self.dkg_signer_count.load(Ordering::SeqCst);

        loop {
            // Check if there are pending requests
            let has_pending = {
                let pending = self.pending_requests.read().await;
                !pending.is_empty()
            };

            if !has_pending {
                break;
            }

            // Try to get a nonce
            let tuple = match self.storage.get_next_available_tuple().await? {
                Some(t) => t,
                None => break, // No more nonces available
            };

            // Skip stale nonces (created with fewer DKG signers than current count)
            let valid = tuple.num_contributors > 0 && tuple.num_contributors >= min_contributors;
            if !valid {
                // Consume the stale nonce so we don't keep hitting it
                self.storage.consume_nonce_tuple(&tuple.tuple_id).await?;
                continue;
            }

            // Consume the nonce
            self.storage.consume_nonce_tuple(&tuple.tuple_id).await?;
            self.storage.record_consumption().await?;

            // Get the next pending request
            let request = {
                let mut pending = self.pending_requests.write().await;
                if pending.is_empty() {
                    // Race condition - put the nonce back? For now just log
                    warn!("⚠️ [NONCE] Consumed nonce but no pending requests (race condition)");
                    break;
                }
                pending.remove(0)
            };

            // Fulfill the request
            let wait_time = request.queued_at.elapsed();
            if request.response_tx.send(tuple.clone()).is_ok() {
                fulfilled += 1;
                info!(
                    "✅ [NONCE] Fulfilled request #{} with nonce {} (waited {:?})",
                    request.request_id, tuple.tuple_id, wait_time
                );
            } else {
                warn!(
                    "⚠️ [NONCE] Request #{} receiver dropped, nonce {} wasted",
                    request.request_id, tuple.tuple_id
                );
            }
        }

        if fulfilled > 0 {
            info!("📊 [NONCE] Fulfilled {} pending requests", fulfilled);
        }

        Ok(fulfilled)
    }

    /// Trigger generation if needed and not already in progress
    async fn maybe_trigger_generation(&self) {
        // Observer nodes never initiate generation.
        if !self.is_dkg_signer.load(Ordering::SeqCst) {
            return;
        }

        // Check if generation is already in progress
        if self.generation_in_progress.swap(true, Ordering::SeqCst) {
            return; // Already generating
        }

        // Check if we need more VALID nonces (not just total count)
        // Stale nonces (created with fewer nodes) don't count!
        let needs_generation = match self.count_valid_nonces().await {
            Ok(count) => {
                if count < self.config.min_pool_size {
                    info!(
                        "🔍 [NONCE] Pool has {} valid nonces (need {}), will generate more",
                        count, self.config.min_pool_size
                    );
                    true
                } else {
                    false
                }
            }
            Err(_) => true,
        };

        if !needs_generation {
            self.generation_in_progress.store(false, Ordering::SeqCst);
            return;
        }

        let round = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        info!("🔄 [NONCE] Triggering background nonce generation (round: {})", round);

        if let Err(e) = self.start_generation(round).await {
            error!("❌ [NONCE] Failed to start generation: {}", e);
        }

        // Note: generation_in_progress will be cleared when batch completes
    }

    /// Pre-generate nonces on startup.
    ///
    /// This should be called after the network is ready (nodes can communicate).
    /// It generates initial nonces to fill the pool before accepting signing requests.
    ///
    /// IMPORTANT: Only counts VALID nonces (num_contributors >= dkg_signer_count).
    /// Stale nonces from previous sessions with fewer DKG signers don't count!
    pub async fn startup_pregenerate(&self) -> Result<()> {
        // Observer nodes get nonces via NonceTupleBroadcast / NoncePoolSync,
        // so they should never initiate the commit-reveal protocol.
        if !self.is_dkg_signer.load(Ordering::SeqCst) {
            info!("⏭️ [NONCE] Observer node — skipping startup_pregenerate (nonces received via broadcast/sync)");
            self.set_startup_ready();
            return Ok(());
        }

        // Count only VALID nonces (not stale ones)
        let valid_count = self.count_valid_nonces().await?;
        let total_count = self.storage.available_nonce_count().await?;
        let stale_count = total_count.saturating_sub(valid_count);

        if stale_count > 0 {
            warn!(
                "⚠️ [NONCE] Found {} stale nonces (created with fewer nodes), they will be ignored",
                stale_count
            );
        }

        if valid_count >= self.config.min_pool_size {
            info!(
                "✅ [NONCE] Pool already has {} valid nonces (min: {}), skipping pre-generation",
                valid_count, self.config.min_pool_size
            );
            self.set_startup_ready();
            return Ok(());
        }

        let needed = self.config.min_pool_size - valid_count;
        let batches_needed = (needed + self.config.batch_size - 1) / self.config.batch_size;

        info!(
            "🚀 [NONCE] Starting pre-generation: need {} nonces ({} batches of {})",
            needed, batches_needed, self.config.batch_size
        );

        // Start the first batch - subsequent batches will be triggered as they complete
        let round = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.generation_in_progress.store(true, Ordering::SeqCst);
        self.start_generation(round).await?;

        info!("🔄 [NONCE] Pre-generation batch started, will continue until pool is filled");

        Ok(())
    }

    /// Check if the nonce pool needs refilling
    ///
    /// IMPORTANT: Only counts VALID nonces (num_contributors >= total_nodes).
    /// Stale nonces (created with fewer nodes) don't count towards the pool size
    /// because they cannot be used for signing.
    pub async fn needs_refill(&self) -> Result<bool> {
        let valid_count = self.count_valid_nonces().await?;
        Ok(valid_count < self.config.min_pool_size)
    }

    /// Count valid nonces in the pool (filtering out stale ones)
    ///
    /// A nonce is valid if num_contributors >= dkg_signer_count.
    /// Stale nonces (created when fewer DKG signers were active) cannot be used.
    pub async fn count_valid_nonces(&self) -> Result<usize> {
        let min_contributors = self.dkg_signer_count.load(Ordering::SeqCst);
        let max_to_check = 2000; // Check up to 2000 nonces
        let available = self.storage.get_available_tuples(max_to_check).await?;

        let valid_count = available
            .iter()
            .filter(|t| t.num_contributors > 0 && t.num_contributors >= min_contributors)
            .count();

        Ok(valid_count)
    }

    /// Get the next available nonce for signing
    /// Returns None if pool is empty (should trigger generation)
    pub async fn acquire_nonce(&self) -> Result<Option<NonceTuple>> {
        let min_contributors = self.dkg_signer_count.load(Ordering::SeqCst);

        // Scan through available nonces to find one with sufficient contributors
        // Stale nonces (created with fewer DKG signers) must be skipped
        let max_to_check = 1000; // Check up to 1000 nonces to find a valid one past stale ones
        let available = self.storage.get_available_tuples(max_to_check).await?;

        for tuple in available {
            // Skip stale nonces (created with fewer DKG signers than current count)
            let valid = tuple.num_contributors > 0 && tuple.num_contributors >= min_contributors;
            if !valid {
                continue; // Skip stale nonce
            }

            // Mark as consumed immediately to prevent reuse
            self.storage.consume_nonce_tuple(&tuple.tuple_id).await?;
            self.storage.record_consumption().await?;

            info!(
                "🔐 [NONCE] Acquired nonce tuple: {} (contributors: {}, pool size: {})",
                tuple.tuple_id,
                tuple.num_contributors,
                self.storage.available_nonce_count().await?
            );

            return Ok(Some(tuple));
        }

        warn!("⚠️ [NONCE] No valid nonces available in pool! (all {} checked were stale or consumed)", max_to_check);
        Ok(None)
    }

    /// Acquire a specific nonce by tuple_id for coordinated signing.
    ///
    /// This method is used when the coordinator has assigned a specific nonce
    /// for a signing operation, and all nodes must use the same nonce.
    ///
    /// Returns:
    /// - Ok(Some(tuple)) if the nonce exists and is available
    /// - Ok(None) if the nonce doesn't exist or is already consumed
    /// - Err if there's a storage error
    pub async fn acquire_specific_nonce(&self, tuple_id: &str) -> Result<Option<NonceTuple>> {
        if let Some(tuple) = self.storage.get_nonce_tuple_by_id(tuple_id).await? {
            if tuple.consumed {
                warn!(
                    "🚫 [NONCE] Requested nonce {} is already consumed — broadcasting invalidation so all nodes remove it from pool",
                    tuple_id
                );
                // Broadcast invalidation to all nodes so no future coordinator
                // can select this nonce again (covers cross-node race where the
                // gossipsub pool-removal arrived too late).
                if let Err(e) = self.broadcast_nonce_invalidation(
                    vec![tuple_id.to_string()],
                    "already consumed during coordinated signing (nonce conflict)",
                ).await {
                    warn!(
                        "⚠️ [NONCE] Failed to broadcast invalidation for consumed nonce {}: {}",
                        tuple_id, e
                    );
                }
                return Ok(None);
            }

            // Mark as consumed immediately to prevent reuse
            self.storage.consume_nonce_tuple(tuple_id).await?;
            self.storage.record_consumption().await?;

            info!(
                "🔐 [NONCE] Acquired specific nonce: {} (pool size: {})",
                tuple_id,
                self.storage.available_nonce_count().await?
            );

            Ok(Some(tuple))
        } else {
            // Nonce not found — this node's pool is out of sync with the coordinator.
            // Broadcast invalidation to ALL nodes so nobody else tries to use this nonce.
            // This prevents the case where 2/3 nodes have the nonce and sign, but 1 doesn't,
            // resulting in an incomplete threshold signature.
            error!(
                "🚫 [NONCE] Nonce {} not found in local pool — broadcasting invalidation to all nodes",
                tuple_id
            );
            if let Err(e) = self.broadcast_nonce_invalidation(
                vec![tuple_id.to_string()],
                "not found in local pool during signing",
            ).await {
                warn!(
                    "⚠️ [NONCE] Failed to broadcast invalidation for missing nonce {}: {}",
                    tuple_id, e
                );
            }
            Ok(None)
        }
    }

    /// Invalidate one or more nonces by marking them as consumed.
    ///
    /// Called when a peer broadcasts a NonceInvalidation message, meaning
    /// some node could not find the nonce during signing.  All nodes must
    /// remove these nonces from their available pool so the coordinator
    /// never selects them again.
    ///
    /// This is **idempotent**: already-consumed or missing nonces are silently
    /// skipped (not an error).
    pub async fn invalidate_nonces(&self, tuple_ids: &[String], reason: &str) {
        for tuple_id in tuple_ids {
            match self.storage.get_nonce_tuple(tuple_id).await {
                Ok(Some(tuple)) => {
                    if tuple.consumed {
                        // Already consumed — nothing to do
                        continue;
                    }
                    if let Err(e) = self.storage.consume_nonce_tuple(tuple_id).await {
                        warn!(
                            "⚠️ [NONCE] Failed to invalidate nonce {}: {}",
                            tuple_id, e
                        );
                    } else {
                        info!(
                            "🚫 [NONCE] Invalidated nonce {} (reason: {})",
                            tuple_id, reason
                        );
                    }
                }
                Ok(None) => {
                    // Nonce doesn't exist locally — expected if this node already
                    // deleted it as stale or never received it
                    info!(
                        "🚫 [NONCE] Nonce {} not found locally, nothing to invalidate (reason: {})",
                        tuple_id, reason
                    );
                }
                Err(e) => {
                    warn!(
                        "⚠️ [NONCE] Error looking up nonce {} for invalidation: {}",
                        tuple_id, e
                    );
                }
            }
        }
    }

    /// Broadcast a nonce invalidation message to all nodes via gossipsub.
    ///
    /// Call this when a coordinated nonce is missing during signing so that
    /// all other nodes also remove it from their available pool.
    pub async fn broadcast_nonce_invalidation(
        &self,
        nonce_tuple_ids: Vec<String>,
        reason: &str,
    ) -> Result<()> {
        if nonce_tuple_ids.is_empty() {
            return Ok(());
        }

        let gossipsub_msg = crate::types::GossipsubMessage::NonceInvalidation {
            nonce_tuple_ids: nonce_tuple_ids.clone(),
            reason: reason.to_string(),
            node_id: self.id.clone(),
        };
        let data = serde_json::to_vec(&gossipsub_msg)?;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: "signing".to_string(),
                data,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to broadcast nonce invalidation: {}", e))?;

        warn!(
            "📢 [NONCE] Broadcasted invalidation for {} nonce(s): {:?} (reason: {})",
            nonce_tuple_ids.len(),
            nonce_tuple_ids,
            reason
        );
        Ok(())
    }

    /// Reserve multiple nonces for a batch of operations.
    ///
    /// This method is used by the coordinator to pre-select nonces for a batch
    /// of signing operations. Returns a map of operation_id -> tuple_id.
    ///
    /// The nonces are NOT consumed yet - they will be consumed when each
    /// node calls acquire_specific_nonce during signing.
    ///
    /// IMPORTANT: Only nonces with num_contributors >= total_nodes are used.
    /// Nonces created when fewer nodes were connected are stale and will fail
    /// because some nodes won't have them in their pool.
    pub async fn reserve_nonces_for_batch(&self, operation_ids: &[String]) -> Result<HashMap<String, String>> {
        let mut assignments = HashMap::new();
        let min_contributors = self.dkg_signer_count.load(Ordering::SeqCst);
        let needed = operation_ids.len();

        info!(
            "🔍 [NONCE] reserve_nonces_for_batch: need {} nonces, dkg_signer_count={}",
            needed, min_contributors
        );

        // Request ALL available nonces to find valid ones among potentially stale ones
        // The issue is stale nonces are at the front of the list, so we need to scan past them
        // We must check ALL nonces because early batches may have been created with fewer nodes
        let max_to_check = 1000; // Check up to 1000 nonces to find valid ones past stale ones
        let available = self.storage.get_available_tuples(max_to_check).await?;

        info!(
            "🔍 [NONCE] reserve_nonces_for_batch: fetched {} nonces from storage",
            available.len()
        );

        // Filter to only use nonces created with all DKG signers participating.
        // Compare against dkg_signer_count (not total_nodes) because observer nodes
        // do NOT participate in the commit-reveal nonce generation protocol.
        let mut valid_nonces = Vec::with_capacity(needed);
        let mut stale_count = 0;

        for t in available {
            let valid = t.num_contributors > 0 && t.num_contributors >= min_contributors;

            if valid {
                info!(
                    "✅ [NONCE] Found valid nonce {} (contributors: {} >= dkg_signer_count={})",
                    t.tuple_id, t.num_contributors, min_contributors
                );
                valid_nonces.push(t);
                if valid_nonces.len() >= needed {
                    break; // We have enough
                }
            } else {
                stale_count += 1;
                // Only log first few stale nonces to avoid spam
                if stale_count <= 3 {
                    warn!(
                        "⚠️ [NONCE] Skipping stale nonce {} (created with {} nodes, need dkg_signer_count={})",
                        t.tuple_id, t.num_contributors, min_contributors
                    );
                }
            }
        }

        if stale_count > 3 {
            warn!(
                "⚠️ [NONCE] Skipped {} stale nonces total (created with fewer nodes than dkg_signer_count={})",
                stale_count, min_contributors
            );
        }

        if valid_nonces.len() < needed {
            warn!(
                "⚠️ [NONCE] Not enough valid nonces available: need {}, have {} (skipped {} stale nonces)",
                needed,
                valid_nonces.len(),
                stale_count
            );
            // Return partial assignments if any are available
        }

        for (op_id, tuple) in operation_ids.iter().zip(valid_nonces.iter()) {
            // CRITICAL: Remove from available IDs so no other reserve_nonces_for_batch
            // call (e.g. the processBatchIntents contract call vs per-intent signing) can
            // select the SAME nonce. We only remove from the available list — we do NOT
            // mark it as consumed yet, because all nodes still need to look it up by ID
            // via acquire_specific_nonce() when they receive the batch broadcast.
            if let Err(e) = self.storage.remove_from_available_ids_public(&tuple.tuple_id).await {
                warn!(
                    "⚠️ [NONCE] Failed to remove reserved nonce {} from available pool for operation {}: {} — skipping",
                    tuple.tuple_id, op_id, e
                );
                continue;
            }
            assignments.insert(op_id.clone(), tuple.tuple_id.clone());
            info!(
                "📋 [NONCE] Reserved nonce {} (contributors: {}) for operation {}",
                tuple.tuple_id, tuple.num_contributors, op_id
            );
        }

        info!(
            "📋 [NONCE] Reserved {} nonces for batch ({} requested, {} valid found, {} stale skipped)",
            assignments.len(),
            needed,
            valid_nonces.len(),
            stale_count
        );

        Ok(assignments)
    }

    /// Remove specific nonce tuple IDs from the available pool.
    ///
    /// Called by **receiving** nodes when they get a batch broadcast that
    /// contains nonce assignments made by the coordinator.  The coordinator
    /// already removed these from its own pool during `reserve_nonces_for_batch`,
    /// but other nodes still have them listed as available.  Without this call
    /// a second coordinator (different observer) can independently select the
    /// same nonce for a different operation, causing "already consumed" errors
    /// when DKG nodes try to sign.
    ///
    /// This does NOT mark the nonce as consumed — only removes it from the
    /// available-IDs list so it won't be picked by future reservation calls.
    pub async fn remove_nonces_from_pool(&self, tuple_ids: &[String]) {
        for tuple_id in tuple_ids {
            if let Err(e) = self.storage.remove_from_available_ids_public(tuple_id).await {
                warn!(
                    "⚠️ [NONCE] Failed to remove nonce {} from available pool: {}",
                    tuple_id, e
                );
            }
        }
        if !tuple_ids.is_empty() {
            info!(
                "🔒 [NONCE] Removed {} nonce(s) from available pool (reserved by coordinator): {:?}",
                tuple_ids.len(),
                tuple_ids
            );
        }
    }

    /// Start a new nonce generation batch
    ///
    /// Generates batch_size nonces in a single commit-reveal cycle
    pub async fn start_generation(&self, round: u64) -> Result<String> {

        // Observer nodes must NOT initiate commit-reveal — they receive nonces
        // via NonceTupleBroadcast instead.
        if !self.is_dkg_signer.load(Ordering::SeqCst) {
            info!("⏭️ [NONCE] Skipping start_generation — this node is not a DKG signer (observer)");
            return Err(anyhow::anyhow!("Observer node cannot start nonce generation"));
        }

        // Don't start nonce generation if the node hasn't discovered peers yet.
        let dkg_signers = self.dkg_signer_count.load(Ordering::SeqCst);
        if dkg_signers == 0 {
            return Err(anyhow::anyhow!(
                "Cannot start nonce generation: dkg_signer_count=0 (not ready)"
            ));
        }

        let batch_id = format!("nonce_{}_{}", round, uuid::Uuid::new_v4());
        let batch_size = self.config.batch_size;
        // Only DKG signers participate in commit-reveal, so use dkg_signer_count
        // as the number of participants (NOT total_nodes which includes observers).
        let initial_total = dkg_signers;

        info!(
            "🚀 [NONCE] Starting nonce generation batch: {} (round: {}, batch_size: {}, dkg_signers: {})",
            batch_id, round, batch_size, initial_total
        );

        // Create batch state with batch_size
        let mut state = NonceGenState::new(
            batch_id.clone(),
            round,
            self.threshold,
            initial_total,
            batch_size,
        );

        // Generate batch_size random (k_i, R_i) pairs and commitments
        let (commitments, local_k_values, local_r_values) = {
            let mut gen = self.generator.lock().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            gen.generate_batch_commitments(&batch_id, batch_size)?
        };

        // Store our local k and R values in the state for later reveal
        state.local_k_values = local_k_values;
        state.local_r_values = local_r_values;
        state.status = NonceGenStatus::CommitmentPhase;

        // Store in active batches
        {
            let mut batches = self.active_batches.write().await;
            batches.insert(batch_id.clone(), state.clone());
        }

        // Persist to storage
        self.storage.store_batch_state(&state).await?;

        // Broadcast commitment message with all commitments
        let msg = SigningMessage::NonceCommitment {
            from: self.id.clone(),
            batch_id: batch_id.clone(),
            round,
            batch_size,
            commitments,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };

        self.broadcast_signing_message(msg).await?;

        Ok(batch_id)
    }

    /// Join an existing nonce generation batch started by the coordinator.
    ///
    /// This is called when we receive a RequestNonceGeneration from another node.
    /// We use THEIR batch_id so all nodes create nonces with the same tuple_ids.
    pub async fn join_generation(&self, batch_id: &str, round: u64, batch_size: usize) -> Result<()> {
        // Observer nodes must NOT participate in commit-reveal.
        if !self.is_dkg_signer.load(Ordering::SeqCst) {
            info!("⏭️ [NONCE] Skipping join_generation for batch {} — not a DKG signer (observer)", batch_id);
            return Ok(());
        }

        // Check if we're already participating in this batch
        {
            let batches = self.active_batches.read().await;
            if batches.contains_key(batch_id) {
                info!(
                    "⏭️ [NONCE] Already participating in batch {}, skipping",
                    batch_id
                );
                return Ok(());
            }
        }

        // Don't join nonce generation if dkg_signer_count is not yet known.
        let dkg_signers = self.dkg_signer_count.load(Ordering::SeqCst);
        if dkg_signers == 0 {
            warn!(
                "⚠️ [NONCE] Cannot join batch {} — dkg_signer_count=0 (not ready)",
                batch_id
            );
            return Err(anyhow::anyhow!(
                "Cannot join nonce generation: dkg_signer_count=0 (not ready)"
            ));
        }

        // Only DKG signers participate, so use dkg_signer_count as participant count
        let initial_total = dkg_signers;

        info!(
            "🤝 [NONCE] Joining nonce generation batch: {} (round: {}, batch_size: {}, dkg_signers: {})",
            batch_id, round, batch_size, initial_total
        );

        // Create batch state with the COORDINATOR'S batch_id
        let mut state = NonceGenState::new(
            batch_id.to_string(),
            round,
            self.threshold,
            initial_total,
            batch_size,
        );

        // Generate batch_size random (k_i, R_i) pairs and commitments
        let (commitments, local_k_values, local_r_values) = {
            let mut gen = self.generator.lock().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            gen.generate_batch_commitments(batch_id, batch_size)?
        };

        // Store our local k and R values in the state for later reveal
        state.local_k_values = local_k_values;
        state.local_r_values = local_r_values;
        state.status = NonceGenStatus::CommitmentPhase;

        // Store in active batches
        {
            let mut batches = self.active_batches.write().await;
            batches.insert(batch_id.to_string(), state.clone());
        }

        // Persist to storage
        self.storage.store_batch_state(&state).await?;

        // Broadcast commitment message with all commitments
        let msg = SigningMessage::NonceCommitment {
            from: self.id.clone(),
            batch_id: batch_id.to_string(),
            round,
            batch_size,
            commitments,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };

        self.broadcast_signing_message(msg).await?;

        Ok(())
    }

    /// Handle an incoming nonce protocol message
    pub async fn handle_message(&self, msg: SigningMessage) -> Result<()> {
        match msg {
            SigningMessage::NonceCommitment {
                from,
                batch_id,
                round,
                batch_size,
                commitments,
                timestamp: _,
            } => {
                self.handle_commitment(&batch_id, &from, commitments, batch_size, round)
                    .await?;
            }

            SigningMessage::NonceReveal {
                from,
                batch_id,
                round,
                r_points,
                k_shares,
                timestamp: _,
            } => {
                self.handle_reveal(&batch_id, &from, &r_points, &k_shares, round).await?;
            }

            SigningMessage::RequestNonceGeneration {
                batch_id,
                round,
                coordinator_id,
                batch_size,
            } => {
                // Another node is requesting nonce generation
                info!(
                    "📥 [NONCE] Received nonce generation request from {}: batch {} (size: {})",
                    coordinator_id, batch_id, batch_size
                );
                // Join the coordinator's batch using THEIR batch_id
                // This ensures all nodes create nonces with the same tuple_ids
                self.join_generation(&batch_id, round, batch_size).await?;
            }

            SigningMessage::NonceGenerationComplete {
                from,
                batch_id,
                round: _,
                tuples_count,
                success,
            } => {
                info!(
                    "✅ [NONCE] Generation complete from {}: batch {} ({} tuples, success: {})",
                    from, batch_id, tuples_count, success
                );
            }

            _ => {
                // Not a nonce message, ignore
            }
        }

        Ok(())
    }

    /// Handle a commitment message from a peer (batch version)
    ///
    /// Each commitment message contains batch_size commitments for batch_size nonces
    async fn handle_commitment(
        &self,
        batch_id: &str,
        from: &str,
        commitments: Vec<[u8; 32]>,
        batch_size: usize,
        round: u64,
    ) -> Result<()> {
        info!(
            "📥 [NONCE] Received {} commitments from {} for batch {}",
            commitments.len(), from, batch_id
        );

        // Check if we have an active batch state, if not, join the batch
        let mut batches = self.active_batches.write().await;
        if !batches.contains_key(batch_id) {
            // Safety check: don't join nonce generation if dkg_signer_count is unknown.
            let dkg_signers = self.dkg_signer_count.load(Ordering::SeqCst);
            if dkg_signers == 0 {
                warn!(
                    "⚠️ [NONCE] Skipping batch {} — dkg_signer_count=0 (not ready). \
                     Will participate after DKG completes.",
                    batch_id
                );
                return Ok(());
            }

            info!(
                "📥 [NONCE] Joining existing batch {} from commitment (batch_size: {}, dkg_signers: {})",
                batch_id, batch_size, dkg_signers
            );

            // Only DKG signers participate, so use dkg_signer_count as participant count
            let initial_total = dkg_signers;

            // Create our own state and generate our (k_i, R_i) pairs
            let mut state = NonceGenState::new(
                batch_id.to_string(),
                round,
                self.threshold,
                initial_total,
                batch_size,
            );

            // Generate batch_size random (k_i, R_i) pairs
            let (our_commitments, local_k_values, local_r_values) = {
                let mut gen = self.generator.lock().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
                gen.generate_batch_commitments(batch_id, batch_size)?
            };

            state.local_k_values = local_k_values;
            state.local_r_values = local_r_values;
            state.status = NonceGenStatus::CommitmentPhase;
            batches.insert(batch_id.to_string(), state.clone());

            // Persist and broadcast our commitments
            drop(batches); // Release lock before async call
            self.storage.store_batch_state(&state).await?;

            let msg = SigningMessage::NonceCommitment {
                from: self.id.clone(),
                batch_id: batch_id.to_string(),
                round,
                batch_size,
                commitments: our_commitments,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            };
            self.broadcast_signing_message(msg).await?;

            // Re-acquire lock
            batches = self.active_batches.write().await;
        }

        if let Some(state) = batches.get_mut(batch_id) {
            // Store all commitments from this peer
            state.commitments.insert(from.to_string(), commitments);

            // Dynamically update total_nodes for this batch.
            // Only DKG signers participate in commit-reveal, so use dkg_signer_count
            // as the authoritative participant count. Fall back to commitments.len()
            // if dkg_signer_count is not yet known.
            let dkg_signers = self.dkg_signer_count.load(Ordering::SeqCst);
            let best_total = if dkg_signers > 0 {
                dkg_signers
            } else {
                state.commitments.len().max(state.total_nodes)
            };
            if best_total > state.total_nodes {
                info!(
                    "📈 [NONCE] Batch {} total_nodes updated {} -> {} (dkg_signers: {}, commitments: {})",
                    batch_id, state.total_nodes, best_total, dkg_signers, state.commitments.len()
                );
                state.total_nodes = best_total;
            }

            // Check if we have threshold commitments
            if state.commitments.len() >= state.threshold && state.status == NonceGenStatus::CommitmentPhase {
                info!(
                    "✅ [NONCE] Reached threshold commitments for batch {} ({}/{}), moving to reveal phase",
                    batch_id, state.commitments.len(), self.threshold
                );
                state.status = NonceGenStatus::RevealPhase;

                // Broadcast our reveal with all R_i and k_i values
                if !state.local_r_values.is_empty() && !state.local_k_values.is_empty() {
                    let r_points: Vec<Vec<u8>> = state.local_r_values.iter()
                        .map(|r| self.serialize_point(&r.0))
                        .collect::<Result<Vec<_>>>()?;

                    let k_shares: Vec<[u8; 32]> = state.local_k_values.iter()
                        .map(|k| k.0.to_bytes().into())
                        .collect();

                    let msg = SigningMessage::NonceReveal {
                        from: self.id.clone(),
                        batch_id: batch_id.to_string(),
                        round,
                        r_points,
                        k_shares,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis(),
                    };
                    drop(batches); // Release lock before async call
                    self.broadcast_signing_message(msg).await?;
                } else {
                    warn!("⚠️ [NONCE] Local k/R values not set for batch {}, cannot reveal", batch_id);
                }
            }
        }

        Ok(())
    }

    /// Handle a reveal message from a peer (batch version)
    ///
    /// Each reveal message contains batch_size (R_i, k_i) pairs.
    /// After threshold reveals, we create batch_size NonceTuples.
    async fn handle_reveal(
        &self,
        batch_id: &str,
        from: &str,
        r_points_bytes: &[Vec<u8>],
        k_shares_bytes: &[[u8; 32]],
        _round: u64,
    ) -> Result<()> {
        info!(
            "📥 [NONCE] Received {} reveals from {} for batch {}",
            r_points_bytes.len(), from, batch_id
        );

        if r_points_bytes.len() != k_shares_bytes.len() {
            return Err(anyhow::anyhow!(
                "Mismatched r_points ({}) and k_shares ({}) count",
                r_points_bytes.len(), k_shares_bytes.len()
            ));
        }

        let batch_size = r_points_bytes.len();

        // Deserialize all R points and k shares
        let mut r_points_decoded = Vec::with_capacity(batch_size);
        let mut k_shares_decoded = Vec::with_capacity(batch_size);

        for (idx, (r_bytes, k_bytes)) in r_points_bytes.iter().zip(k_shares_bytes.iter()).enumerate() {
            let r_point = self.deserialize_point(r_bytes)?;
            let k_share = self.deserialize_scalar(k_bytes)?;

            // Verify R_i = k_i * G
            let expected_r = (ProjectivePoint::GENERATOR * k_share).to_affine();
            if expected_r != r_point {
                error!(
                    "❌ [NONCE] k_share[{}] doesn't match R point for {} in batch {}",
                    idx, from, batch_id
                );
                return Err(anyhow::anyhow!("k_share verification failed at index {}: R_i != k_i * G", idx));
            }

            r_points_decoded.push(SerializablePoint(r_point));
            k_shares_decoded.push(SerializableScalar(k_share));
        }

        // Update batch state with all R_i and k_i values from this peer
        let mut batches = self.active_batches.write().await;
        if let Some(state) = batches.get_mut(batch_id) {
            state.r_points.insert(from.to_string(), r_points_decoded);
            state.k_shares.insert(from.to_string(), k_shares_decoded);

            // Dynamically update total_nodes (same logic as handle_commitment).
            // Only DKG signers participate, so use dkg_signer_count as authoritative count.
            let dkg_signers = self.dkg_signer_count.load(Ordering::SeqCst);
            let best_total = if dkg_signers > 0 {
                dkg_signers
            } else {
                state.commitments.len().max(state.total_nodes)
            };
            if best_total > state.total_nodes {
                info!(
                    "📈 [NONCE] Batch {} total_nodes updated {} -> {} during reveal (dkg_signers: {}, commitments: {})",
                    batch_id, state.total_nodes, best_total, dkg_signers, state.commitments.len()
                );
                state.total_nodes = best_total;
            }

            // Check if we have ALL reveals from all DKG signer nodes.
            // Only DKG signers participate in nonce commit-reveal (observers are excluded).
            // We need reveals from ALL DKG signers so every signer computes the same
            // aggregated_k = Σk_i over the same set of k_i values.
            //
            // Use dkg_signer_count as the authoritative participant count.
            // Fall back to commitments.len() (ground truth of actual participants)
            // if dkg_signer_count is not yet known.
            let dkg_signers = self.dkg_signer_count.load(Ordering::SeqCst);
            let committed_peers = state.commitments.len();
            let effective_total = if dkg_signers > 0 {
                dkg_signers
            } else {
                // Fallback: use number of actual committed peers
                committed_peers.max(state.total_nodes)
            };

            // We need reveals from (effective_total - 1) peers since we have our own local values.
            // At minimum, we need at least 1 reveal (never 0) to produce a valid multi-party nonce.
            let expected_reveals = effective_total.saturating_sub(1).max(1);

            info!(
                "📊 [NONCE] Batch {} reveal progress: {}/{} peers (effective_total: {}, dkg_signers: {}, committed: {})",
                batch_id, state.r_points.len(), expected_reveals, effective_total, dkg_signers, committed_peers
            );

            if state.r_points.len() >= expected_reveals && state.k_shares.len() >= expected_reveals {
                info!(
                    "✅ [NONCE] Received ALL reveals for batch {} ({}/{} peers), creating {} nonce tuples",
                    batch_id, state.r_points.len(), expected_reveals, state.batch_size
                );

                // Create batch_size NonceTuples
                let mut tuples = Vec::with_capacity(state.batch_size);

                for idx in 0..state.batch_size {
                    // Compute aggregate R[idx] = Σ R_i[idx] for this index
                    // IMPORTANT: Include BOTH other peers' R values AND our own local R values
                    let mut aggregate_r_proj = ProjectivePoint::IDENTITY;

                    // Add R values from other peers
                    for (_peer, r_points) in &state.r_points {
                        if idx < r_points.len() {
                            aggregate_r_proj += ProjectivePoint::from(r_points[idx].0);
                        }
                    }

                    // Add our own local R value
                    if idx < state.local_r_values.len() {
                        aggregate_r_proj += ProjectivePoint::from(state.local_r_values[idx].0);
                    }

                    let aggregate_r = aggregate_r_proj.to_affine();

                    // Compute aggregate k[idx] = Σ k_i[idx] for this index
                    // IMPORTANT: Include BOTH other peers' k values AND our own local k values
                    let mut aggregated_k = Scalar::ZERO;

                    // Add k shares from other peers
                    for (_peer, k_shares) in &state.k_shares {
                        if idx < k_shares.len() {
                            aggregated_k += k_shares[idx].0;
                        }
                    }

                    // Add our own local k value
                    if idx < state.local_k_values.len() {
                        aggregated_k += state.local_k_values[idx].0;
                    }

                    if aggregated_k == Scalar::ZERO {
                        error!("❌ [NONCE] Aggregated k[{}] is zero", idx);
                        continue;
                    }

                    // Compute k⁻¹
                    let k_inv: Scalar = match aggregated_k.invert().into() {
                        Some(inv) => inv,
                        None => {
                            error!("❌ [NONCE] Aggregated k[{}] is not invertible", idx);
                            continue;
                        }
                    };

                    // Compute r = x(R) mod n
                    let r_scalar = self.compute_r_scalar(&aggregate_r)?;

                    // CRITICAL VERIFICATION: Ensure r_scalar is valid for ECDSA recovery
                    // For signature recovery to work, we need r to be a valid x-coordinate
                    // on secp256k1, or r + n to be valid (when r + n < p).
                    //
                    // secp256k1 parameters:
                    // p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
                    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                    //
                    // A value x is a valid x-coordinate iff y² = x³ + 7 (mod p) is a quadratic residue.
                    // We check using the Legendre symbol: (y²)^((p-1)/2) ≡ 1 (mod p).
                    if !self.is_valid_r_for_recovery(&r_scalar) {
                        warn!(
                            "⚠️ [NONCE] Tuple {}_{} SKIPPED: r_scalar is not valid for ECDSA recovery\n\
                             \t  r_scalar: 0x{}\n\
                             \t  This happens rarely (~1 in 2^128) when x(R) mod n produces an invalid x-coordinate.\n\
                             \t  Generating another nonce in its place.",
                            batch_id, idx,
                            hex::encode(r_scalar.to_bytes())
                        );
                        continue; // Skip this nonce - it would produce unrecoverable signatures
                    }

                    // CRITICAL VERIFICATION: Ensure R = k * G
                    // If this fails, the nonce is corrupted and signatures will be invalid
                    let expected_r = (ProjectivePoint::GENERATOR * aggregated_k).to_affine();
                    if expected_r != aggregate_r {
                        error!(
                            "❌❌❌ [NONCE] CRITICAL: R != k*G verification FAILED for tuple {}_{}\n\
                             \tExpected R (from k*G): 0x{}\n\
                             \tActual aggregate_r:    0x{}\n\
                             \tThis indicates a bug in nonce aggregation - signatures will fail!",
                            batch_id, idx,
                            hex::encode(expected_r.to_encoded_point(true).as_bytes()),
                            hex::encode(aggregate_r.to_encoded_point(true).as_bytes())
                        );
                        continue; // Skip this corrupted nonce
                    }

                    // Log the aggregated k and r_scalar for debugging nonce coordination
                    // All nodes MUST have the same aggregated_k and r_scalar values
                    info!(
                        "🟣🟣🟣 [NONCE-CREATE] Tuple {}_{} CREATED 🟣🟣🟣\n\
                         ╔══════════════════════════════════════════════════════════════════╗\n\
                         ║  aggregated_k (first 8 bytes): 0x{}                ║\n\
                         ║  k_inv (first 8 bytes):        0x{}                ║\n\
                         ║  r_scalar:                     0x{}  ║\n\
                         ║  r_y_parity:                   {}                                   ║\n\
                         ║  R=k*G verification:           ✓                                   ║\n\
                         ╚══════════════════════════════════════════════════════════════════╝",
                        batch_id, idx,
                        hex::encode(&aggregated_k.to_bytes()[..8]),
                        hex::encode(&k_inv.to_bytes()[..8]),
                        hex::encode(r_scalar.to_bytes()),
                        self.get_y_parity(&aggregate_r)
                    );

                    // Count includes other peers + our own local values
                    let num_contributors = state.k_shares.len() + 1;

                    let tuple = NonceTuple {
                        tuple_id: format!("{}_{}", batch_id, idx),
                        aggregated_k: SerializableScalar(aggregated_k),
                        k_inv: SerializableScalar(k_inv),
                        aggregate_r: SerializablePoint(aggregate_r),
                        r_scalar: SerializableScalar(r_scalar),
                        r_y_parity: self.get_y_parity(&aggregate_r),
                        consumed: false,
                        created_at: chrono::Utc::now().timestamp(),
                        batch_id: batch_id.to_string(),
                        num_contributors,
                    };

                    tuples.push(tuple);
                }

                let tuples_count = tuples.len();
                // Count includes other peers + our own local values
                let total_contributors = state.k_shares.len() + 1;
                info!(
                    "🎉🟣 [NONCE-BATCH] Created {} nonce tuples for batch {} (from {} nodes: {} peers + this node) 🟣🎉",
                    tuples_count, batch_id, total_contributors, state.k_shares.len()
                );

                drop(batches); // Release lock before async calls

                // Store all tuples
                let tuples_for_broadcast = tuples.clone();
                for tuple in tuples {
                    self.storage.store_nonce_tuple(&tuple).await?;
                }

                // Broadcast finalized tuples to all nodes (including observers)
                // so they can reserve nonce IDs when acting as final node.
                if let Err(e) = self.broadcast_nonce_tuples(batch_id, tuples_for_broadcast).await {
                    warn!(
                        "⚠️ [NONCE] Failed to broadcast nonce tuples for batch {}: {}",
                        batch_id, e
                    );
                }

                // Cleanup batch
                self.storage.cleanup_batch(batch_id).await?;

                // Mark generation as complete
                self.generation_in_progress.store(false, Ordering::SeqCst);

                // Fulfill any pending requests
                let fulfilled = self.fulfill_pending_requests().await?;
                if fulfilled > 0 {
                    info!(
                        "📊 [NONCE] Batch {} complete: created {} nonces, fulfilled {} pending requests",
                        batch_id, tuples_count, fulfilled
                    );
                }

                // Check if pool still needs more nonces (continue pre-generation if needed)
                // Use count_valid_nonces to exclude stale nonces
                let valid_count = self.count_valid_nonces().await?;
                if valid_count < self.config.min_pool_size {
                    info!(
                        "🔄 [NONCE] Pool still low ({} valid/{} min), triggering more generation",
                        valid_count, self.config.min_pool_size
                    );
                    self.maybe_trigger_generation().await;
                } else if !self.is_startup_ready() {
                    // Pool is full enough, mark startup as ready
                    self.set_startup_ready();
                }
            }
        }

        Ok(())
    }

    /// Compute r = x(R) mod n
    fn compute_r_scalar(&self, r_point: &AffinePoint) -> Result<Scalar> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let encoded = r_point.to_encoded_point(false);
        let x_bytes = encoded.x().ok_or_else(|| anyhow::anyhow!("Point at infinity"))?;

        // Convert x coordinate to scalar (mod n)
        // Use Reduce (not ReduceNonZero) to get proper r = x(R) mod n without the +1 adjustment
        let x_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        Ok(x_scalar)
    }

    /// Check if an r_scalar value is valid for ECDSA signature recovery.
    ///
    /// For ECDSA recovery to work, we need to find a point R on the curve such that
    /// x(R) ≡ r (mod n). This means either:
    /// 1. r is a valid x-coordinate on secp256k1, OR
    /// 2. r + n is a valid x-coordinate AND r + n < p
    ///
    /// A value x is a valid x-coordinate on secp256k1 iff y² = x³ + 7 (mod p) is a
    /// quadratic residue (i.e., has a square root in Fp).
    ///
    /// We check this using the Legendre symbol: (y²)^((p-1)/2) ≡ 1 (mod p) means
    /// y² is a quadratic residue.
    ///
    /// This check prevents creating nonces that would produce unrecoverable signatures.
    fn is_valid_r_for_recovery(&self, r_scalar: &Scalar) -> bool {
        use num_bigint::BigUint;

        // secp256k1 field prime
        let p = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        ).unwrap();

        // secp256k1 group order
        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        ).unwrap();

        let r = BigUint::from_bytes_be(&r_scalar.to_bytes());

        // Check if r is a valid x-coordinate
        // y² = r³ + 7 (mod p)
        let r_cubed = r.modpow(&BigUint::from(3u32), &p);
        let y_squared = (&r_cubed + BigUint::from(7u32)) % &p;

        // Legendre symbol: y²^((p-1)/2) mod p
        // = 1 if quadratic residue, = p-1 if non-residue, = 0 if y² = 0
        let exp = (&p - BigUint::from(1u32)) / BigUint::from(2u32);
        let legendre = y_squared.modpow(&exp, &p);

        if legendre == BigUint::from(1u32) {
            return true; // r is a valid x-coordinate
        }

        // Check if r + n is a valid x-coordinate (for recovery_id >= 2)
        let r_plus_n = &r + &n;
        if r_plus_n >= p {
            return false; // r + n >= p, no alternative recovery possible
        }

        // Check if r + n is a valid x-coordinate
        let r_plus_n_cubed = r_plus_n.modpow(&BigUint::from(3u32), &p);
        let y_squared_2 = (&r_plus_n_cubed + BigUint::from(7u32)) % &p;
        let legendre_2 = y_squared_2.modpow(&exp, &p);

        legendre_2 == BigUint::from(1u32)
    }

    /// Get Y-parity of a point for recovery ID
    fn get_y_parity(&self, point: &AffinePoint) -> u8 {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let encoded = point.to_encoded_point(true);
        // Compressed form: 0x02 for even y, 0x03 for odd y
        if encoded.as_bytes()[0] == 0x03 {
            1
        } else {
            0
        }
    }

    /// Serialize a point for transmission
    fn serialize_point(&self, point: &AffinePoint) -> Result<Vec<u8>> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        Ok(point.to_encoded_point(true).as_bytes().to_vec())
    }

    /// Deserialize a point from bytes
    fn deserialize_point(&self, bytes: &[u8]) -> Result<AffinePoint> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        use k256::EncodedPoint;

        let encoded =
            EncodedPoint::from_bytes(bytes).map_err(|_| anyhow::anyhow!("Invalid point bytes"))?;

        Option::from(AffinePoint::from_encoded_point(&encoded))
            .ok_or_else(|| anyhow::anyhow!("Invalid curve point"))
    }

    /// Deserialize a scalar from bytes
    ///
    /// Uses `Scalar::from_repr()` which is the proper inverse of `to_bytes()`.
    /// This ensures the scalar is correctly reconstructed without modular reduction.
    fn deserialize_scalar(&self, bytes: &[u8; 32]) -> Result<Scalar> {
        // Convert to FieldBytes (which is a GenericArray<u8, 32>)
        let field_bytes = FieldBytes::from_slice(bytes);

        // Use from_repr which is the inverse of to_bytes()
        // This properly handles the canonical representation
        let scalar_opt: Option<Scalar> = Scalar::from_repr(*field_bytes).into();

        scalar_opt.ok_or_else(|| anyhow::anyhow!("Invalid scalar bytes - not in canonical form"))
    }

    /// Broadcast a signing message via gossipsub
    async fn broadcast_signing_message(&self, msg: SigningMessage) -> Result<()> {
        let gossipsub_msg = crate::types::GossipsubMessage::Signing(msg);
        let data = serde_json::to_vec(&gossipsub_msg)?;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: "signing".to_string(),
                data,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to broadcast: {}", e))?;

        Ok(())
    }

    /// Broadcast finalized nonce tuples to all nodes via gossipsub.
    /// Observer nodes store these so they can reserve nonce IDs as final node.
    async fn broadcast_nonce_tuples(&self, batch_id: &str, tuples: Vec<NonceTuple>) -> Result<()> {
        let gossipsub_msg = crate::types::GossipsubMessage::NonceTupleBroadcast {
            batch_id: batch_id.to_string(),
            tuples,
            node_id: self.id.clone(),
        };
        let data = serde_json::to_vec(&gossipsub_msg)?;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: "signing".to_string(),
                data,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to broadcast nonce tuples: {}", e))?;

        info!(
            "📤 [NONCE] Broadcasted finalized nonce tuples for batch {} to all nodes",
            batch_id
        );
        Ok(())
    }

    /// Store a nonce tuple received via broadcast from another node.
    /// Used by observer nodes to populate their nonce pool for final-node coordination.
    /// DKG nodes may also receive these (harmless duplicate — already stored during generation).
    pub async fn store_received_nonce_tuple(&self, tuple: NonceTuple) -> Result<()> {
        // Skip if already stored (DKG nodes store during generation)
        if self.storage.get_nonce_tuple(&tuple.tuple_id).await?.is_some() {
            return Ok(());
        }
        self.storage.store_nonce_tuple(&tuple).await?;
        Ok(())
    }

    /// Get current pool status
    pub async fn pool_status(&self) -> Result<(usize, usize)> {
        let available = self.storage.available_nonce_count().await?;
        Ok((available, self.config.min_pool_size))
    }

    /// Get all available (unconsumed) nonce tuples for syncing to observer nodes.
    /// Called by a DKG node when an observer requests nonce pool sync via RPC.
    pub async fn get_available_tuples_for_sync(&self) -> Result<Vec<NonceTuple>> {
        let max_to_serve = 1000;
        self.storage.get_available_tuples(max_to_serve).await
    }

    /// Acquire a nonce, blocking until one is available.
    ///
    /// This method:
    /// 1. First checks if a nonce is already available in the pool
    /// 2. If not, starts nonce generation and waits for it to complete
    /// 3. Returns the acquired nonce (never returns None)
    ///
    /// The wait is implemented by polling the storage for available nonces
    /// with a short sleep between checks. This allows the async commit-reveal
    /// protocol to complete via message handling.
    pub async fn acquire_nonce_blocking(&self, timeout_ms: u64) -> Result<NonceTuple> {
        // First, try to get an existing nonce
        if let Some(tuple) = self.storage.get_next_available_tuple().await? {
            // Mark as consumed immediately to prevent reuse
            self.storage.consume_nonce_tuple(&tuple.tuple_id).await?;
            self.storage.record_consumption().await?;

            info!(
                "🔐 [NONCE] Acquired existing nonce tuple: {} (pool size: {})",
                tuple.tuple_id,
                self.storage.available_nonce_count().await?
            );

            return Ok(tuple);
        }

        // No nonces available - start generation
        let round = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        info!(
            "⏳ [NONCE] No nonces available, starting generation and waiting (timeout: {}ms)...",
            timeout_ms
        );

        // Start the generation process
        let batch_id = self.start_generation(round).await?;
        info!("🚀 [NONCE] Started generation batch: {}", batch_id);

        // Poll for available nonces with timeout
        let start = std::time::Instant::now();
        let poll_interval_ms = 100; // Check every 100ms

        loop {
            // Check if timeout exceeded
            if start.elapsed().as_millis() as u64 > timeout_ms {
                error!(
                    "❌ [NONCE] Timed out waiting for nonce generation ({}ms)",
                    timeout_ms
                );
                return Err(anyhow::anyhow!(
                    "Nonce generation timeout after {}ms",
                    timeout_ms
                ));
            }

            // Sleep briefly to allow messages to be processed
            tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;

            // Check if a nonce is now available
            if let Some(tuple) = self.storage.get_next_available_tuple().await? {
                // Mark as consumed immediately to prevent reuse
                self.storage.consume_nonce_tuple(&tuple.tuple_id).await?;
                self.storage.record_consumption().await?;

                info!(
                    "🔐 [NONCE] Acquired newly generated nonce: {} (waited: {}ms)",
                    tuple.tuple_id,
                    start.elapsed().as_millis()
                );

                return Ok(tuple);
            }

            // Log progress every second
            let elapsed = start.elapsed().as_secs();
            if elapsed > 0 && start.elapsed().as_millis() % 1000 < poll_interval_ms as u128 {
                info!(
                    "⏳ [NONCE] Still waiting for nonce generation... ({}s elapsed)",
                    elapsed
                );
            }
        }
    }

    /// Get the configured timeout for blocking acquisition
    pub fn get_phase_timeout_ms(&self) -> u64 {
        self.config.phase_timeout_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the stale nonce filtering works correctly
    #[tokio::test]
    async fn test_reserve_nonces_filters_stale_nonces() {
        use crate::database::{Database, DatabaseConfig};
        use tempfile::tempdir;

        // Create a temp database
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            encryption_key: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()),
            ..Default::default()
        };
        let db = Database::new(config).unwrap();
        let storage = NonceStorage::new(db);

        // Create mock channel (won't be used in this test)
        let (tx, _rx) = mpsc::channel(1);

        // Create manager with 3 total nodes
        let manager = NonceManager::new(
            "test_node".to_string(),
            2,  // threshold
            3,  // total_nodes
            3,  // dkg_signer_count
            storage.clone(),
            tx,
            NoncePoolConfig::default(),
        );

        // Create some "stale" nonces (created with only 2 nodes)
        for i in 0..5 {
            let stale_tuple = NonceTuple {
                tuple_id: format!("stale_nonce_{}", i),
                aggregated_k: SerializableScalar(Scalar::ONE),
                k_inv: SerializableScalar(Scalar::ONE),
                aggregate_r: SerializablePoint(k256::AffinePoint::GENERATOR),
                r_scalar: SerializableScalar(Scalar::ONE),
                r_y_parity: 0,
                consumed: false,
                created_at: chrono::Utc::now().timestamp(),
                batch_id: "stale_batch".to_string(),
                num_contributors: 2,  // Only 2 nodes contributed - stale!
            };
            storage.store_nonce_tuple(&stale_tuple).await.unwrap();
        }

        // Create some "valid" nonces (created with 3 nodes)
        for i in 0..5 {
            let valid_tuple = NonceTuple {
                tuple_id: format!("valid_nonce_{}", i),
                aggregated_k: SerializableScalar(Scalar::ONE),
                k_inv: SerializableScalar(Scalar::ONE),
                aggregate_r: SerializablePoint(k256::AffinePoint::GENERATOR),
                r_scalar: SerializableScalar(Scalar::ONE),
                r_y_parity: 0,
                consumed: false,
                created_at: chrono::Utc::now().timestamp(),
                batch_id: "valid_batch".to_string(),
                num_contributors: 3,  // 3 nodes contributed - valid!
            };
            storage.store_nonce_tuple(&valid_tuple).await.unwrap();
        }

        // Now try to reserve 3 nonces
        let op_ids = vec![
            "op1".to_string(),
            "op2".to_string(),
            "op3".to_string(),
        ];

        let assignments = manager.reserve_nonces_for_batch(&op_ids).await.unwrap();

        // Should get 3 valid nonces, skipping the stale ones
        assert_eq!(assignments.len(), 3, "Should reserve 3 nonces");

        // All reserved nonces should be from the valid batch
        for (_, tuple_id) in &assignments {
            assert!(
                tuple_id.starts_with("valid_nonce_"),
                "Reserved nonce {} should be from valid batch, not stale",
                tuple_id
            );
        }

        println!("✅ test_reserve_nonces_filters_stale_nonces passed!");
    }

    /// Test that nonce reservation works when there are not enough valid nonces
    #[tokio::test]
    async fn test_reserve_nonces_partial_when_insufficient() {
        use crate::database::{Database, DatabaseConfig};
        use tempfile::tempdir;

        // Create a temp database
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            encryption_key: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()),
            ..Default::default()
        };
        let db = Database::new(config).unwrap();
        let storage = NonceStorage::new(db);

        // Create mock channel
        let (tx, _rx) = mpsc::channel(1);

        // Create manager with 3 total nodes
        let manager = NonceManager::new(
            "test_node".to_string(),
            2,
            3,
            3,  // dkg_signer_count
            storage.clone(),
            tx,
            NoncePoolConfig::default(),
        );

        // Create only 2 valid nonces
        for i in 0..2 {
            let valid_tuple = NonceTuple {
                tuple_id: format!("valid_nonce_{}", i),
                aggregated_k: SerializableScalar(Scalar::ONE),
                k_inv: SerializableScalar(Scalar::ONE),
                aggregate_r: SerializablePoint(k256::AffinePoint::GENERATOR),
                r_scalar: SerializableScalar(Scalar::ONE),
                r_y_parity: 0,
                consumed: false,
                created_at: chrono::Utc::now().timestamp(),
                batch_id: "valid_batch".to_string(),
                num_contributors: 3,
            };
            storage.store_nonce_tuple(&valid_tuple).await.unwrap();
        }

        // Create 10 stale nonces
        for i in 0..10 {
            let stale_tuple = NonceTuple {
                tuple_id: format!("stale_nonce_{}", i),
                aggregated_k: SerializableScalar(Scalar::ONE),
                k_inv: SerializableScalar(Scalar::ONE),
                aggregate_r: SerializablePoint(k256::AffinePoint::GENERATOR),
                r_scalar: SerializableScalar(Scalar::ONE),
                r_y_parity: 0,
                consumed: false,
                created_at: chrono::Utc::now().timestamp(),
                batch_id: "stale_batch".to_string(),
                num_contributors: 2,  // Only 2 nodes - stale
            };
            storage.store_nonce_tuple(&stale_tuple).await.unwrap();
        }

        // Try to reserve 5 nonces
        let op_ids: Vec<String> = (0..5).map(|i| format!("op{}", i)).collect();

        let assignments = manager.reserve_nonces_for_batch(&op_ids).await.unwrap();

        // Should only get 2 (the valid ones)
        assert_eq!(assignments.len(), 2, "Should only reserve 2 valid nonces");

        println!("✅ test_reserve_nonces_partial_when_insufficient passed!");
    }

    /// Test that update_total_nodes works correctly
    #[test]
    fn test_update_total_nodes() {
        use tempfile::tempdir;
        use crate::database::{Database, DatabaseConfig};

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            encryption_key: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()),
            ..Default::default()
        };
        let db = Database::new(config).unwrap();
        let storage = NonceStorage::new(db);

        let (tx, _rx) = mpsc::channel(1);

        let manager = NonceManager::new(
            "test_node".to_string(),
            2,
            2,  // Start with 2 nodes
            2,  // dkg_signer_count
            storage,
            tx,
            NoncePoolConfig::default(),
        );

        assert_eq!(manager.get_total_nodes(), 2);

        // Update to 3 nodes
        manager.update_total_nodes(3);
        assert_eq!(manager.get_total_nodes(), 3);

        // Update back to 2
        manager.update_total_nodes(2);
        assert_eq!(manager.get_total_nodes(), 2);

        println!("✅ test_update_total_nodes passed!");
    }

    /// Test that is_valid_r_for_recovery correctly identifies invalid r values
    #[test]
    fn test_is_valid_r_for_recovery() {
        use tempfile::tempdir;
        use crate::database::{Database, DatabaseConfig};

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            encryption_key: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()),
            ..Default::default()
        };
        let db = Database::new(config).unwrap();
        let storage = NonceStorage::new(db);

        let (tx, _rx) = mpsc::channel(1);

        let manager = NonceManager::new(
            "test_node".to_string(),
            2,
            3,
            3,  // dkg_signer_count
            storage,
            tx,
            NoncePoolConfig::default(),
        );

        // Test 1: Known invalid r_scalar from the bug report
        // 0x464fcda34c052d332405c932baa2daed2366d9dd42770023bdbb829bf5ab6605
        let invalid_r_bytes: [u8; 32] = [
            0x46, 0x4f, 0xcd, 0xa3, 0x4c, 0x05, 0x2d, 0x33,
            0x24, 0x05, 0xc9, 0x32, 0xba, 0xa2, 0xda, 0xed,
            0x23, 0x66, 0xd9, 0xdd, 0x42, 0x77, 0x00, 0x23,
            0xbd, 0xbb, 0x82, 0x9b, 0xf5, 0xab, 0x66, 0x05,
        ];
        let invalid_r = Scalar::from_repr(*FieldBytes::from_slice(&invalid_r_bytes)).unwrap();
        assert!(
            !manager.is_valid_r_for_recovery(&invalid_r),
            "Known invalid r should be rejected"
        );
        println!("✅ Known invalid r correctly rejected");

        // Test 2: The generator point's x-coordinate should be valid
        // G = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        let g_x_bytes: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
            0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
            0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let g_x = Scalar::from_repr(*FieldBytes::from_slice(&g_x_bytes)).unwrap();
        assert!(
            manager.is_valid_r_for_recovery(&g_x),
            "Generator's x-coordinate should be valid"
        );
        println!("✅ Generator's x-coordinate correctly accepted");

        // Test 3: Random nonces from k * G should produce valid r values
        // (since R = k*G is always on the curve, and with Reduce the r_scalar matches x(R))
        use k256::ProjectivePoint;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use num_bigint::BigUint;

        for i in 1..10u64 {
            let k = Scalar::from(i);
            let r_point = (ProjectivePoint::GENERATOR * k).to_affine();
            let r_scalar = manager.compute_r_scalar(&r_point).unwrap();

            // Get the actual x-coordinate and verify r_scalar matches
            let encoded = r_point.to_encoded_point(false);
            let x_bytes = encoded.x().unwrap();
            let x_coord = BigUint::from_bytes_be(x_bytes);
            let r_value = BigUint::from_bytes_be(&r_scalar.to_bytes());

            // With Reduce (not ReduceNonZero), r_scalar should equal x(R) when x(R) < n
            let n = BigUint::parse_bytes(
                b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                16,
            ).unwrap();

            if x_coord < n {
                assert_eq!(
                    x_coord, r_value,
                    "r_scalar should equal x(R) when x(R) < n"
                );
            }

            // Verify that R = k*G points produce valid r values for recovery
            let is_valid = manager.is_valid_r_for_recovery(&r_scalar);
            println!("k={}: is_valid for recovery: {}", i, is_valid);

            // All R = k*G points should produce valid r values (since R is on the curve)
            assert!(
                is_valid,
                "k={}: r_scalar from R=k*G should be valid for recovery",
                i
            );
        }

        println!("✅ test_is_valid_r_for_recovery passed!");
    }

    /// Test that delete_stale_nonces removes nonces with fewer contributors
    #[tokio::test]
    async fn test_delete_stale_nonces() {
        use tempfile::tempdir;
        use crate::database::{Database, DatabaseConfig};

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            encryption_key: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()),
            ..Default::default()
        };
        let db = Database::new(config).unwrap();
        let storage = NonceStorage::new(db);

        // Create 5 nonces with 2 contributors (will be stale when 3rd node joins)
        for i in 0..5 {
            let tuple = NonceTuple {
                tuple_id: format!("two_node_nonce_{}", i),
                aggregated_k: SerializableScalar(Scalar::ONE),
                k_inv: SerializableScalar(Scalar::ONE),
                aggregate_r: SerializablePoint(k256::AffinePoint::GENERATOR),
                r_scalar: SerializableScalar(Scalar::ONE),
                r_y_parity: 0,
                consumed: false,
                created_at: chrono::Utc::now().timestamp(),
                batch_id: "two_node_batch".to_string(),
                num_contributors: 2,
            };
            storage.store_nonce_tuple(&tuple).await.unwrap();
        }

        // Create 3 nonces with 3 contributors (valid even after 3rd node joins)
        for i in 0..3 {
            let tuple = NonceTuple {
                tuple_id: format!("three_node_nonce_{}", i),
                aggregated_k: SerializableScalar(Scalar::ONE),
                k_inv: SerializableScalar(Scalar::ONE),
                aggregate_r: SerializablePoint(k256::AffinePoint::GENERATOR),
                r_scalar: SerializableScalar(Scalar::ONE),
                r_y_parity: 0,
                consumed: false,
                created_at: chrono::Utc::now().timestamp(),
                batch_id: "three_node_batch".to_string(),
                num_contributors: 3,
            };
            storage.store_nonce_tuple(&tuple).await.unwrap();
        }

        // Verify we have 8 nonces total
        let count_before = storage.available_nonce_count().await.unwrap();
        assert_eq!(count_before, 8, "Should have 8 nonces before deletion");

        // Delete stale nonces (those with < 3 contributors)
        let deleted = storage.delete_stale_nonces(3).await.unwrap();
        assert_eq!(deleted, 5, "Should delete 5 stale nonces");

        // Verify only 3 nonces remain
        let count_after = storage.available_nonce_count().await.unwrap();
        assert_eq!(count_after, 3, "Should have 3 nonces after deletion");

        // Verify the remaining nonces are the 3-contributor ones
        let remaining = storage.get_available_tuples(10).await.unwrap();
        for tuple in remaining {
            assert_eq!(tuple.num_contributors, 3, "Remaining nonces should have 3 contributors");
            assert!(tuple.tuple_id.starts_with("three_node_nonce_"), "Remaining should be 3-node nonces");
        }

        println!("✅ test_delete_stale_nonces passed!");
    }

    /// Test that handle_node_joined deletes stale nonces and updates total
    #[tokio::test]
    async fn test_handle_node_joined() {
        use tempfile::tempdir;
        use crate::database::{Database, DatabaseConfig};

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            encryption_key: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()),
            ..Default::default()
        };
        let db = Database::new(config).unwrap();
        let storage = NonceStorage::new(db);

        let (tx, _rx) = mpsc::channel(100);

        // Create manager with 2 nodes initially
        let manager = NonceManager::new(
            "test_node".to_string(),
            2,  // threshold
            2,  // total_nodes - start with 2
            2,  // dkg_signer_count
            storage.clone(),
            tx,
            NoncePoolConfig::default(),
        );

        // Verify initial state
        assert_eq!(manager.get_total_nodes(), 2);

        // Create nonces with 2 contributors
        for i in 0..5 {
            let tuple = NonceTuple {
                tuple_id: format!("old_nonce_{}", i),
                aggregated_k: SerializableScalar(Scalar::ONE),
                k_inv: SerializableScalar(Scalar::ONE),
                aggregate_r: SerializablePoint(k256::AffinePoint::GENERATOR),
                r_scalar: SerializableScalar(Scalar::ONE),
                r_y_parity: 0,
                consumed: false,
                created_at: chrono::Utc::now().timestamp(),
                batch_id: "old_batch".to_string(),
                num_contributors: 2,
            };
            storage.store_nonce_tuple(&tuple).await.unwrap();
        }

        // Verify nonces exist
        let count_before = storage.available_nonce_count().await.unwrap();
        assert_eq!(count_before, 5, "Should have 5 nonces before node join");

        // Simulate a 3rd node joining
        manager.handle_node_joined(3).await.unwrap();

        // Verify total_nodes updated
        assert_eq!(manager.get_total_nodes(), 3);

        // Verify all old nonces were deleted (they had only 2 contributors)
        let count_after = storage.available_nonce_count().await.unwrap();
        assert_eq!(count_after, 0, "All old nonces should be deleted after node join");

        println!("✅ test_handle_node_joined passed!");
    }

    /// Test that handle_node_joined does NOT delete nonces when node count decreases
    #[tokio::test]
    async fn test_handle_node_joined_no_op_on_decrease() {
        use tempfile::tempdir;
        use crate::database::{Database, DatabaseConfig};

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            encryption_key: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()),
            ..Default::default()
        };
        let db = Database::new(config).unwrap();
        let storage = NonceStorage::new(db);

        let (tx, _rx) = mpsc::channel(100);

        // Create manager with 3 nodes
        let manager = NonceManager::new(
            "test_node".to_string(),
            2,
            3,  // Start with 3 nodes
            3,  // dkg_signer_count
            storage.clone(),
            tx,
            NoncePoolConfig::default(),
        );

        // Create nonces with 3 contributors
        for i in 0..5 {
            let tuple = NonceTuple {
                tuple_id: format!("good_nonce_{}", i),
                aggregated_k: SerializableScalar(Scalar::ONE),
                k_inv: SerializableScalar(Scalar::ONE),
                aggregate_r: SerializablePoint(k256::AffinePoint::GENERATOR),
                r_scalar: SerializableScalar(Scalar::ONE),
                r_y_parity: 0,
                consumed: false,
                created_at: chrono::Utc::now().timestamp(),
                batch_id: "good_batch".to_string(),
                num_contributors: 3,
            };
            storage.store_nonce_tuple(&tuple).await.unwrap();
        }

        // Simulate node leaving (decrease from 3 to 2)
        manager.handle_node_joined(2).await.unwrap();

        // Should NOT delete any nonces (only delete on increase)
        let count = storage.available_nonce_count().await.unwrap();
        assert_eq!(count, 5, "Nonces should NOT be deleted when node count decreases");

        // total_nodes should still be updated
        assert_eq!(manager.get_total_nodes(), 2);

        println!("✅ test_handle_node_joined_no_op_on_decrease passed!");
    }
}
