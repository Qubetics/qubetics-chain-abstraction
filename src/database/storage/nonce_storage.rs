use crate::database::{keys, Database};
use crate::types::nonce::{NonceGenState, NoncePoolMetrics, NonceTuple};
use crate::types::secp::SerializablePoint;
use anyhow::Result;
use std::collections::HashMap;
use tracing::info;

/// Storage for nonce tuples and generation state.
///
/// This module handles persistence of:
/// - Pre-computed nonce tuples ready for signing
/// - Nonce generation batch states
/// - Commitments and R points during generation
/// - Pool metrics for monitoring
#[derive(Clone)]
pub struct NonceStorage {
    db: Database,
}

impl NonceStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ============================================================
    // Nonce Tuple Management
    // ============================================================

    /// Store a ready-to-use nonce tuple
    pub async fn store_nonce_tuple(&self, tuple: &NonceTuple) -> Result<()> {
        let key = format!("{}{}", keys::NONCE_TUPLE, tuple.tuple_id);
        self.db.put_string(&key, tuple)?;

        // Add to available IDs list if not consumed
        if !tuple.consumed {
            self.add_to_available_ids(&tuple.tuple_id).await?;
        }

        info!(
            "💾 [NONCE_STORAGE] Stored nonce tuple: {} (consumed: {})",
            tuple.tuple_id, tuple.consumed
        );
        Ok(())
    }

    /// Get a specific nonce tuple by ID
    pub async fn get_nonce_tuple(&self, tuple_id: &str) -> Result<Option<NonceTuple>> {
        let key = format!("{}{}", keys::NONCE_TUPLE, tuple_id);
        self.db.get_string(&key)
    }

    /// Alias for get_nonce_tuple for clearer semantics in coordinated signing
    pub async fn get_nonce_tuple_by_id(&self, tuple_id: &str) -> Result<Option<NonceTuple>> {
        self.get_nonce_tuple(tuple_id).await
    }

    /// Get up to `count` available (unconsumed) nonce tuples
    /// Used by coordinator to pre-select nonces for a batch
    pub async fn get_available_tuples(&self, count: usize) -> Result<Vec<NonceTuple>> {
        let available_ids = self.get_available_ids().await?;
        let mut tuples = Vec::with_capacity(count.min(available_ids.len()));

        for id in available_ids.iter().take(count) {
            if let Some(tuple) = self.get_nonce_tuple(id).await? {
                if !tuple.consumed {
                    tuples.push(tuple);
                }
            }
        }

        Ok(tuples)
    }

    /// Get the next available (unconsumed) nonce tuple
    /// Returns None if no nonces are available
    pub async fn get_next_available_tuple(&self) -> Result<Option<NonceTuple>> {
        let available_ids = self.get_available_ids().await?;

        for id in available_ids {
            if let Some(tuple) = self.get_nonce_tuple(&id).await? {
                if !tuple.consumed {
                    return Ok(Some(tuple));
                }
            }
        }

        Ok(None)
    }

    /// Mark a nonce tuple as consumed (used for signing)
    /// CRITICAL: Once consumed, a nonce must NEVER be reused
    pub async fn consume_nonce_tuple(&self, tuple_id: &str) -> Result<()> {
        let key = format!("{}{}", keys::NONCE_TUPLE, tuple_id);

        if let Some(mut tuple) = self.db.get_string::<NonceTuple>(&key)? {
            if tuple.consumed {
                return Err(anyhow::anyhow!(
                    "SECURITY: Attempted to consume already-consumed nonce: {}",
                    tuple_id
                ));
            }

            tuple.consumed = true;
            self.db.put_string(&key, &tuple)?;

            // Remove from available IDs
            self.remove_from_available_ids(tuple_id).await?;

            info!(
                "🔒 [NONCE_STORAGE] Consumed nonce tuple: {} (NEVER reuse)",
                tuple_id
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!("Nonce tuple not found: {}", tuple_id))
        }
    }

    /// Get count of available (unconsumed) nonces
    pub async fn available_nonce_count(&self) -> Result<usize> {
        let available_ids = self.get_available_ids().await?;
        Ok(available_ids.len())
    }

    /// Get all available nonce tuple IDs
    async fn get_available_ids(&self) -> Result<Vec<String>> {
        self.db
            .get_string::<Vec<String>>(keys::NONCE_AVAILABLE_IDS)
            .map(|opt| opt.unwrap_or_default())
    }

    /// Add a tuple ID to the available list
    async fn add_to_available_ids(&self, tuple_id: &str) -> Result<()> {
        let mut ids = self.get_available_ids().await?;
        if !ids.contains(&tuple_id.to_string()) {
            ids.push(tuple_id.to_string());
            self.db.put_string(keys::NONCE_AVAILABLE_IDS, &ids)?;
        }
        Ok(())
    }

    /// Remove a tuple ID from the available list (internal use by consume_nonce_tuple)
    async fn remove_from_available_ids(&self, tuple_id: &str) -> Result<()> {
        let mut ids = self.get_available_ids().await?;
        ids.retain(|id| id != tuple_id);
        self.db.put_string(keys::NONCE_AVAILABLE_IDS, &ids)?;
        Ok(())
    }

    /// Remove a tuple ID from the available list without marking it consumed.
    ///
    /// Used by the coordinator during `reserve_nonces_for_batch()` to prevent
    /// the same nonce from being selected by multiple sequential reservation
    /// calls within the same epoch (e.g. processBatchIntents contract call
    /// vs per-intent UserToVault signing). The nonce data remains in storage
    /// so that all nodes can still look it up by ID via `acquire_specific_nonce()`.
    pub async fn remove_from_available_ids_public(&self, tuple_id: &str) -> Result<()> {
        self.remove_from_available_ids(tuple_id).await
    }

    /// Delete old consumed nonces to free storage
    pub async fn cleanup_consumed_nonces(&self, older_than_secs: i64) -> Result<usize> {
        let prefix = keys::NONCE_TUPLE;
        let results: Vec<(String, NonceTuple)> = self.db.get_values_with_prefix(prefix)?;
        let now = chrono::Utc::now().timestamp();
        let mut deleted = 0;

        for (key, tuple) in results {
            if tuple.consumed && (now - tuple.created_at) > older_than_secs {
                self.db.delete_string(&key)?;
                deleted += 1;
            }
        }

        if deleted > 0 {
            info!(
                "🗑️ [NONCE_STORAGE] Cleaned up {} old consumed nonces",
                deleted
            );
        }

        Ok(deleted)
    }

    /// Delete all stale nonces (those with fewer contributors than required).
    ///
    /// This is called when a new node joins the network. All nonces generated
    /// without that node's participation must be deleted because the new node
    /// doesn't have them in its database and cannot use them for signing.
    ///
    /// Returns the number of nonces deleted.
    pub async fn delete_stale_nonces(&self, min_contributors: usize) -> Result<usize> {
        let prefix = keys::NONCE_TUPLE;
        let results: Vec<(String, NonceTuple)> = self.db.get_values_with_prefix(prefix)?;
        let mut deleted = 0;
        let mut stale_ids = Vec::new();

        for (key, tuple) in results {
            // Delete nonces with fewer contributors than required
            // Also delete nonces with num_contributors = 0 (legacy nonces without this field)
            if tuple.num_contributors < min_contributors {
                self.db.delete_string(&key)?;
                stale_ids.push(tuple.tuple_id.clone());
                deleted += 1;
            }
        }

        // Remove deleted IDs from available list
        if !stale_ids.is_empty() {
            let mut available_ids = self.get_available_ids().await?;
            let original_len = available_ids.len();
            available_ids.retain(|id| !stale_ids.contains(id));
            if available_ids.len() != original_len {
                self.db.put_string(keys::NONCE_AVAILABLE_IDS, &available_ids)?;
            }

            info!(
                "🗑️ [NONCE_STORAGE] Deleted {} stale nonces (had <{} contributors)",
                deleted, min_contributors
            );
        }

        Ok(deleted)
    }

    // ============================================================
    // Nonce Generation Batch State
    // ============================================================

    /// Store nonce generation batch state
    pub async fn store_batch_state(&self, state: &NonceGenState) -> Result<()> {
        let key = format!("{}{}", keys::NONCE_BATCH, state.batch_id);
        self.db.put_string(&key, state)?;
        info!(
            "💾 [NONCE_STORAGE] Stored batch state: {} (status: {:?})",
            state.batch_id, state.status
        );
        Ok(())
    }

    /// Get nonce generation batch state
    pub async fn get_batch_state(&self, batch_id: &str) -> Result<Option<NonceGenState>> {
        let key = format!("{}{}", keys::NONCE_BATCH, batch_id);
        self.db.get_string(&key)
    }

    /// Delete batch state after completion
    pub async fn delete_batch_state(&self, batch_id: &str) -> Result<()> {
        let key = format!("{}{}", keys::NONCE_BATCH, batch_id);
        self.db.delete_string(&key)?;
        info!("🗑️ [NONCE_STORAGE] Deleted batch state: {}", batch_id);
        Ok(())
    }

    // ============================================================
    // Commitment Storage (Phase 1 of nonce generation)
    // ============================================================

    /// Store a commitment from a peer during nonce generation
    pub async fn store_commitment(
        &self,
        batch_id: &str,
        from_peer: &str,
        commitment: [u8; 32],
    ) -> Result<()> {
        let key = format!("{}{}:{}", keys::NONCE_COMMITMENT, batch_id, from_peer);
        self.db.put_string(&key, &commitment.to_vec())?;
        info!(
            "💾 [NONCE_STORAGE] Stored commitment from {} for batch {}",
            from_peer, batch_id
        );
        Ok(())
    }

    /// Get all commitments for a batch
    pub async fn get_commitments(&self, batch_id: &str) -> Result<HashMap<String, [u8; 32]>> {
        let prefix = format!("{}{}:", keys::NONCE_COMMITMENT, batch_id);
        let results: Vec<(String, Vec<u8>)> = self.db.get_values_with_prefix(&prefix)?;
        let mut map = HashMap::new();

        for (key, bytes) in results {
            if let Some(peer_id) = key.strip_prefix(&prefix) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    map.insert(peer_id.to_string(), arr);
                }
            }
        }

        Ok(map)
    }

    /// Clear commitments for a batch
    pub async fn clear_commitments(&self, batch_id: &str) -> Result<()> {
        let prefix = format!("{}{}:", keys::NONCE_COMMITMENT, batch_id);
        let keys_vec = self.db.get_keys_with_prefix(&prefix)?;
        for key in keys_vec {
            self.db.delete_string(&key)?;
        }
        info!(
            "🗑️ [NONCE_STORAGE] Cleared commitments for batch {}",
            batch_id
        );
        Ok(())
    }

    // ============================================================
    // R Point Storage (Phase 2 of nonce generation)
    // ============================================================

    /// Store an R point from a peer after reveal phase
    pub async fn store_r_point(
        &self,
        batch_id: &str,
        from_peer: &str,
        r_point: &SerializablePoint,
    ) -> Result<()> {
        let key = format!("{}{}:{}", keys::NONCE_R_POINT, batch_id, from_peer);
        self.db.put_string(&key, r_point)?;
        info!(
            "💾 [NONCE_STORAGE] Stored R point from {} for batch {}",
            from_peer, batch_id
        );
        Ok(())
    }

    /// Get all R points for a batch
    pub async fn get_r_points(&self, batch_id: &str) -> Result<HashMap<String, SerializablePoint>> {
        let prefix = format!("{}{}:", keys::NONCE_R_POINT, batch_id);
        let results: Vec<(String, SerializablePoint)> = self.db.get_values_with_prefix(&prefix)?;
        let mut map = HashMap::new();

        for (key, point) in results {
            if let Some(peer_id) = key.strip_prefix(&prefix) {
                map.insert(peer_id.to_string(), point);
            }
        }

        Ok(map)
    }

    /// Clear R points for a batch
    pub async fn clear_r_points(&self, batch_id: &str) -> Result<()> {
        let prefix = format!("{}{}:", keys::NONCE_R_POINT, batch_id);
        let keys_vec = self.db.get_keys_with_prefix(&prefix)?;
        for key in keys_vec {
            self.db.delete_string(&key)?;
        }
        info!("🗑️ [NONCE_STORAGE] Cleared R points for batch {}", batch_id);
        Ok(())
    }

    // ============================================================
    // Pool Metrics
    // ============================================================

    /// Store pool metrics
    pub async fn store_metrics(&self, metrics: &NoncePoolMetrics) -> Result<()> {
        self.db.put_string(keys::NONCE_POOL_METRICS, metrics)?;
        Ok(())
    }

    /// Get pool metrics
    pub async fn get_metrics(&self) -> Result<NoncePoolMetrics> {
        self.db
            .get_string::<NoncePoolMetrics>(keys::NONCE_POOL_METRICS)
            .map(|opt| opt.unwrap_or_default())
    }

    /// Update metrics after generating nonces
    pub async fn record_generation(&self, count: usize, duration_ms: u64) -> Result<()> {
        let mut metrics = self.get_metrics().await?;
        metrics.total_generated += count as u64;
        metrics.available_count = self.available_nonce_count().await?;
        metrics.last_generation_at = Some(chrono::Utc::now().timestamp());

        // Update average generation time
        let total_gens = metrics.total_generated;
        if total_gens > 0 {
            metrics.avg_generation_time_ms =
                (metrics.avg_generation_time_ms * (total_gens - count as u64) + duration_ms)
                    / total_gens;
        }

        self.store_metrics(&metrics).await?;
        Ok(())
    }

    /// Update metrics after consuming a nonce
    pub async fn record_consumption(&self) -> Result<()> {
        let mut metrics = self.get_metrics().await?;
        metrics.total_consumed += 1;
        metrics.available_count = self.available_nonce_count().await?;
        metrics.last_consumed_at = Some(chrono::Utc::now().timestamp());
        self.store_metrics(&metrics).await?;
        Ok(())
    }

    /// Record a failed generation attempt
    pub async fn record_failed_generation(&self) -> Result<()> {
        let mut metrics = self.get_metrics().await?;
        metrics.failed_generations += 1;
        self.store_metrics(&metrics).await?;
        Ok(())
    }

    // ============================================================
    // Cleanup
    // ============================================================

    /// Clean up all data for a completed or failed batch
    pub async fn cleanup_batch(&self, batch_id: &str) -> Result<()> {
        self.clear_commitments(batch_id).await?;
        self.clear_r_points(batch_id).await?;
        self.delete_batch_state(batch_id).await?;
        info!("🧹 [NONCE_STORAGE] Cleaned up batch: {}", batch_id);
        Ok(())
    }
}
