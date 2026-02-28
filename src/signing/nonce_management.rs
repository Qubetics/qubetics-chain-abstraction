use super::*;
use anyhow::Result;
use std::sync::Arc;
use tracing::{error, info, warn};
pub use chains::{BitcoinSigner, TicsSigner};
pub use config::{BroadcastConfig, ChainBroadcastConfig};
pub use coordination::Coordination;
pub use db_signing::DatabaseSigningNode;
pub use key::KeyStore;
pub use state::{
    BroadcastPolicy, BtcAggregationState, BtcRoundExtras, BtcUtvAggregationState, PendingStore,
    PendingValue, RoundSlotKey, SignatureStore, SigningEnvironmentBuilder,
};
pub use nonce::{NonceGenerator, NonceManager};

impl SigningNode {
    /// Handle a new node joining - delete stale nonces and regenerate.
    ///
    /// When a new node joins, all existing nonces become stale because
    /// the new node doesn't have them. This method:
    /// 1. Deletes all stale nonces
    /// 2. Triggers immediate nonce regeneration with all nodes
    ///
    /// This ensures all nodes have the same nonces after a new node joins.
    pub async fn handle_nonce_manager_node_joined(&self, new_total: usize) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            if let Err(e) = mgr.handle_node_joined(new_total).await {
                warn!("⚠️ [SIGNING] Failed to handle node join in NonceManager: {}", e);
            }
        }
    }

    /// Flush the entire nonce pool (called on DKG node restart).
    /// The node may have missed NonceInvalidation messages while offline,
    /// so all old nonces are deleted. A fresh pool is synced from a peer afterwards.
    pub async fn flush_nonce_pool(&self) -> Result<usize> {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.flush_all_nonces().await
        } else {
            Ok(0)
        }
    }

    /// Start pre-generating nonces on startup.
    ///
    /// This should be called after the network is ready and nodes can communicate.
    /// It fills the nonce pool before accepting signing requests.
    ///
    /// Returns immediately after starting the generation process - the actual
    /// generation happens asynchronously via the commit-reveal protocol.
    pub async fn start_nonce_pregeneration(&self) -> anyhow::Result<()> {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.startup_pregenerate().await?;
            info!("🚀 [SIGNING] Started nonce pre-generation");
            Ok(())
        } else {
            warn!("⚠️ [SIGNING] Cannot start pre-generation - NonceManager not initialized");
            Err(anyhow::anyhow!("NonceManager not initialized"))
        }
    }

    /// Check if nonce pre-generation is complete and pool is ready.
    pub async fn is_nonce_pool_ready(&self) -> bool {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.is_startup_ready()
        } else {
            false
        }
    }

    /// Acquire a nonce from the pool for signing.
    ///
    /// This method uses a queue-based approach:
    /// 1. If nonces are available, returns one immediately
    /// 2. If pool is empty, queues the request and waits for generation
    /// 3. Never returns None due to empty pool - will wait for generation
    ///
    /// Returns None only if:
    /// - NonceManager is not initialized
    /// - Nonce generation times out (after configured timeout)
    pub async fn try_acquire_nonce(&self) -> Option<crate::types::nonce::NonceTuple> {
        if let Some(manager) = &self.nonce_manager {
            // Use the queue-based request_nonce which handles waiting
            let mgr = manager.lock().await;
            match mgr.request_nonce().await {
                Ok(nonce) => {
                    info!(
                        "🔐 [SIGNING] Acquired nonce {} for signing",
                        nonce.tuple_id
                    );
                    Some(nonce)
                }
                Err(e) => {
                    error!(
                        "❌ [SIGNING] Failed to acquire nonce: {}",
                        e
                    );
                    error!("❌ [SIGNING] CRITICAL: Cannot sign without nonce - refusing to use fixed k");
                    None
                }
            }
        } else {
            warn!("⚠️ [SIGNING] NonceManager not initialized");
            None
        }
    }

    /// Check if the nonce pool needs refilling and trigger generation if needed.
    /// Call this during idle periods (e.g., epoch_3).
    pub async fn check_and_refill_nonce_pool(&self, current_round: u64) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            match mgr.needs_refill().await {
                Ok(true) => {
                    info!(
                        "🔄 [SIGNING] Nonce pool low, triggering generation for round {}",
                        current_round
                    );
                    if let Err(e) = mgr.start_generation(current_round).await {
                        warn!("[SIGNING] Failed to start nonce generation: {}", e);
                    }
                }
                Ok(false) => {
                    // Pool is sufficiently filled
                }
                Err(e) => {
                    warn!("[SIGNING] Failed to check nonce pool status: {}", e);
                }
            }
        }
    }

    /// Invalidate nonces locally (idempotent) and optionally broadcast to all nodes.
    ///
    /// Call this when a coordinated nonce is missing during signing.
    /// The broadcast ensures all other nodes also remove the nonce from their pool.
    pub async fn invalidate_and_broadcast_nonces(
        &self,
        nonce_tuple_ids: Vec<String>,
        reason: &str,
    ) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            // Invalidate locally first
            mgr.invalidate_nonces(&nonce_tuple_ids, reason).await;
            // Broadcast to all nodes
            if let Err(e) = mgr
                .broadcast_nonce_invalidation(nonce_tuple_ids, reason)
                .await
            {
                warn!(
                    "⚠️ [SIGNING] Failed to broadcast nonce invalidation: {}",
                    e
                );
            }
        }
    }

    /// Invalidate nonces locally only (no broadcast).
    /// Used when processing a NonceInvalidation gossipsub message from another node.
    pub async fn invalidate_nonces_local(&self, nonce_tuple_ids: &[String], reason: &str) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.invalidate_nonces(nonce_tuple_ids, reason).await;
        }
    }

    /// Remove nonce tuple IDs from the local available pool.
    ///
    /// Called by receiving nodes when they get a batch broadcast containing
    /// nonce assignments from the coordinator. Prevents a second coordinator
    /// from independently selecting the same nonce for a different operation.
    pub async fn remove_nonces_from_available_pool(&self, tuple_ids: &[String]) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.remove_nonces_from_pool(tuple_ids).await;
        }
    }

    /// Initialize the nonce manager for random k generation.
    /// Call this after set_database() since NonceStorage requires a database.
    ///
    /// `dkg_signer_count`: number of DKG signers that participate in nonce generation.
    /// On DKG nodes this equals `total_nodes` at genesis; on observer nodes it is
    /// the count received from PeerList RPC.  Used for stale-nonce filtering.
    pub fn init_nonce_manager(&mut self, total_nodes: usize, dkg_signer_count: usize) {
        if let Some(db) = &self.database {
            let nonce_storage = crate::database::storage::NonceStorage::new((*db.clone()).clone());
            let config = crate::types::nonce::NoncePoolConfig::default();

            let manager = nonce::NonceManager::new(
                self.id.clone(),
                self.threshold,
                total_nodes,
                dkg_signer_count,
                nonce_storage,
                self.message_tx.clone(),
                config,
            );

            self.nonce_manager = Some(Arc::new(tokio::sync::Mutex::new(manager)));

            info!(
                "🎲 [SIGNING] Node {} nonce manager initialized (threshold: {}, total: {}, dkg_signer_count: {})",
                self.id, self.threshold, total_nodes, dkg_signer_count
            );
        } else {
            warn!(
                "⚠️ [SIGNING] Cannot init nonce manager - database not set for node {}",
                self.id
            );
        }
    }

    /// Get a reference to the nonce manager (if initialized)
    pub fn nonce_manager(&self) -> Option<&Arc<tokio::sync::Mutex<nonce::NonceManager>>> {
        self.nonce_manager.as_ref()
    }

    /// Update the NonceManager's total_nodes count.
    ///
    /// Call this when nodes join or leave the network.
    /// This ensures the NonceManager filters out stale nonces correctly.
    ///
    /// IMPORTANT: For node joins, use `handle_nonce_manager_node_joined` instead!
    /// That method deletes stale nonces and triggers regeneration.
    pub async fn update_nonce_manager_total_nodes(&self, new_total: usize) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.update_total_nodes(new_total);
        }
    }

    /// Update the NonceManager's dkg_signer_count.
    ///
    /// Called when DKG completes or when existing DKG shares are loaded from disk
    /// to ensure nonce generation uses the correct peer count for threshold checks.
    pub async fn update_nonce_dkg_signer_count(&self, count: usize) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.update_dkg_signer_count(count);
        }
    }

    /// Mark the NonceManager as belonging to a DKG signer (or not).
    ///
    /// Only DKG signers initiate the commit-reveal nonce generation protocol.
    /// Observer nodes passively receive nonces via NonceTupleBroadcast.
    pub async fn set_nonce_manager_dkg_signer(&self, is_signer: bool) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.set_is_dkg_signer(is_signer);
        }
    }

}
