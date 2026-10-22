use anyhow::{anyhow, ensure, Result};
use k256::{ProjectivePoint, Scalar};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::artifacts::{DKGCompletionCallback, DKGStatus};
use crate::database::DkgStorage;
use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{
    ChannelMessage, GossipsubMessage, KeyShare, SerializablePoint, SerializableScalar,
};
use crate::DKGMessage::*;
use crate::NodeMembership;
use k256::AffinePoint;

#[derive(Clone)]
struct DKGState {
    status: DKGStatus,
    threshold: usize,
    total_nodes: usize,
    my_permanent_index: Option<usize>, // Index assigned during initial DKG, never changes
}

pub struct DKGNode {
    pub(super) id: String,
    state: Arc<RwLock<DKGState>>,
    pub(super) storage: DkgStorage,
    pub(super) message_tx: mpsc::Sender<ChannelMessage>,
    pub(super) completion_callback: Option<DKGCompletionCallback>,
    pub(super) chain_code: [u8; 32],
}

impl DKGNode {
    pub(crate) fn total_nodes(&self) -> usize {
        self.state.read().unwrap().total_nodes
    }

    pub(crate) fn threshold(&self) -> usize {
        self.state.read().unwrap().threshold
    }

    pub(super) fn set_permanent_index(&self, index: usize) {
        let mut state = self.state.write().unwrap();
        if let Some(existing) = state.my_permanent_index {
            if existing != index {
                warn!(
                    "🔁 [DKG] Overwriting permanent index from {} to {}",
                    existing, index
                );
            }
        }
        state.my_permanent_index = Some(index);
    }

    pub(super) fn transition_status(&self, next: DKGStatus) -> Result<()> {
        fn is_valid_transition(current: &DKGStatus, next: &DKGStatus) -> bool {
            use DKGStatus::*;
            match (current, next) {
                // Staying in the same state is harmless
                (a, b) if std::mem::discriminant(a) == std::mem::discriminant(b) => true,
                (New, Started | Completed | New | Error { .. }) => true,
                (Started, Completed | Error { .. } | Started) => true,
                (Completed, New | Completed | Error { .. }) => true,
                (Error { .. }, New | Error { .. }) => true,
                _ => false,
            }
        }

        let mut state = self.state.write().unwrap();
        if !is_valid_transition(&state.status, &next) {
            let err = anyhow!(
                "Invalid DKG status transition: {:?} -> {:?}",
                state.status,
                next
            );
            warn!("{}", err);
            return Err(err);
        }
        state.status = next;
        Ok(())
    }

    pub fn new(
        id: String,
        threshold: usize,
        total_nodes: usize,
        message_tx: mpsc::Sender<ChannelMessage>,
        storage: DkgStorage,
        chain_code: [u8; 32],
    ) -> Self {
        let state = DKGState {
            status: DKGStatus::New,
            threshold,
            total_nodes,
            my_permanent_index: None,
        };
        Self {
            id,
            state: Arc::new(RwLock::new(state)),
            storage,
            message_tx,
            completion_callback: None,
            chain_code,
        }
    }

    /// Load permanent index from storage
    pub async fn load_permanent_index(&mut self) -> Result<()> {
        if let Some(index) = self.storage.get_my_permanent_index().await? {
            self.set_permanent_index(index);
            info!("🔢 [DKG] Loaded permanent index: {}", index);
        }
        Ok(())
    }


    /// Restore in-memory DKG status to Completed from persisted storage.
    /// Called when a main DKG node restarts and already has valid DKG data on disk.
    /// Does NOT delete any data - only restores the in-memory state.
    pub async fn restore_completed_state(&mut self) -> Result<()> {
        // Verify critical data exists in storage before restoring
        let has_secret = self.storage.get_final_secret().await?.is_some();
        let has_public = self.storage.get_final_public().await?.is_some();
        let has_index = self.storage.get_my_permanent_index().await?.is_some();

        if !has_secret || !has_public || !has_index {
            return Err(anyhow!(
                "Cannot restore DKG state: missing critical data (secret={}, public={}, index={})",
                has_secret,
                has_public,
                has_index
            ));
        }

        self.transition_status(DKGStatus::Completed)?;
        info!("✅ [RECONNECT] Restored DKG status to Completed from persisted storage");
        Ok(())
    }

    pub fn set_completion_callback(&mut self, callback: DKGCompletionCallback) {
        self.completion_callback = Some(callback);
        info!("🔗 [DKG] Node {} set completion callback", self.id);
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

    pub fn get_status(&self) -> DKGStatus {
        self.state.read().unwrap().status.clone()
    }

    pub fn update_node_params(&mut self, total_nodes: usize, threshold: usize) -> Result<()> {
        info!(
            "🔄 Updating DKGNode params: total_nodes = {}, threshold = {}",
            total_nodes, threshold
        );
        ensure!(total_nodes > 0, "total_nodes must be greater than zero");
        ensure!(
            threshold > 0 && threshold <= total_nodes,
            "threshold {} must be between 1 and total_nodes {}",
            threshold,
            total_nodes
        );
        let mut state = self.state.write().unwrap();
        state.total_nodes = total_nodes;
        state.threshold = threshold;
        Ok(())
    }

    pub async fn get_final_secret_share(&self) -> Option<Scalar> {
        self.storage.get_final_secret().await.unwrap_or_default()
    }

    pub async fn get_final_public_key(&self) -> Option<ProjectivePoint> {
        self.storage.get_final_public().await.unwrap_or_default()
    }

    /// Store the final public key (network group key) - used by observer nodes receiving it via PeerList
    pub async fn set_final_public_key(&self, public_key: ProjectivePoint) -> Result<()> {
        self.storage.set_final_public(public_key).await
    }

    pub async fn get_vault_tweaked_secret_share(&self) -> Option<Scalar> {
        self.storage
            .get_vault_tweaked_secret()
            .await
            .unwrap_or_default()
    }

    pub async fn get_vault_group_key(&self) -> Option<ProjectivePoint> {
        self.storage.get_vault_group_key().await.unwrap_or_default()
    }

    /// Store the vault group key (used by observer nodes receiving it via PeerList)
    pub async fn set_vault_group_key(&self, vault_group_key: ProjectivePoint) -> Result<()> {
        self.storage.set_vault_group_key(vault_group_key).await
    }

    /// Store the liquidity operator ETH/BTC addresses (used by observer nodes receiving via PeerList)
    pub async fn set_liquidity_operator_addresses(
        &self,
        eth_address: &str,
        btc_address: &str,
    ) -> Result<()> {
        self.storage
            .set_liquidity_operator_addresses(eth_address, btc_address)
            .await
    }

    pub async fn is_completed(&self) -> bool {
        matches!(self.state.read().unwrap().status, DKGStatus::Completed)
    }

    pub async fn is_initial_dkg_complete(&self) -> bool {
        self.storage
            .is_initial_dkg_complete()
            .await
            .unwrap_or(false)
    }

    /// Mark initial DKG as complete (used by observer nodes that learn about DKG from PeerList)
    pub async fn mark_initial_dkg_complete(&self) -> Result<()> {
        self.storage.set_initial_dkg_complete(true).await
    }

    /// Get the number of initial DKG signers (sync, from storage)
    pub fn get_dkg_signer_count(&self) -> Option<usize> {
        self.storage.get_dkg_signer_count().ok().flatten()
    }

    /// Set the number of initial DKG signers (used when receiving from PeerList on observer nodes)
    pub fn set_dkg_signer_count(&self, count: usize) -> Result<()> {
        self.storage.set_dkg_signer_count(count)
    }

    /// Get the node's ID
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Get peer index for a given peer ID (for secure share distribution)
    pub fn get_peer_index_for(&self, peer_id: &str) -> Result<Option<usize>> {
        self.storage.get_peer_index_for(peer_id)
    }

    pub async fn process_incoming_share(
        &mut self,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<bool> {
        info!(
            "🔐 [DKG-SECURE] Processing unicast share index {} from {}",
            share_index, from_node_id
        );

        // Check for duplicate share (per-session dedup, reset clears this)
        if self.storage.is_share_received(&from_node_id).await? {
            warn!(
                "⚠️ [DKG-SECURE] Duplicate share from {} (already received), ignoring",
                from_node_id
            );
            return Ok(false);
        }

        // Get our own index to verify this share is for us
        let my_index = match self.storage.get_peer_index_for(&self.id) {
            Ok(Some(idx)) => idx,
            _ => {
                warn!("❌ [DKG-SECURE] Cannot determine own peer index");
                return Err(anyhow!("Cannot determine own peer index"));
            }
        };
        // Verify the share is intended for us
        if share_index != my_index {
            warn!(
                "❌ [DKG-SECURE] Received share for wrong index: {} (expected {})",
                share_index, my_index
            );
            return Ok(false);
        }

        // Enforce the use of strictly broadcast commitments from storage, preventing inline spoofing
        let verification_commitments: Vec<SerializablePoint> = match self
            .storage
            .get_commitments_for(&from_node_id)
            .await
        {
            Ok(Some(stored)) => stored.into_iter().map(SerializablePoint).collect(),
            _ => {
                warn!(
                    "❌ [DKG-SECURE] No authenticated broadcast commitments available for {} (yet). Waiting for Gossipsub broadcast.",
                    from_node_id
                );
                return Ok(false);
            }
        };

        // Verify the share against commitments (cryptographic guarantee)
        if self.verify_share(&share_value, share_index, &verification_commitments) {
            let key_share = KeyShare {
                index: share_index,
                value: share_value,
            };

            self.storage.store_share(&from_node_id, &key_share).await?;

            let raw_commitments: Vec<AffinePoint> =
                verification_commitments.iter().map(|c| c.0).collect();
            self.storage
                .store_commitments(&from_node_id, &raw_commitments)
                .await?;

            self.storage.mark_share_received(&from_node_id).await?;

            self.handle_share_validation(self.id.clone(), from_node_id.clone(), true, node_manager)
                .await?;

            // Broadcast validation
            let validation_msg = ShareValidation {
                from: self.id.clone(),
                to: from_node_id.clone(),
                is_valid: true,
            };
            let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
            let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
            self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;

            info!(
                "📡 [DKG-SECURE] Broadcasted ShareValidation (valid) for {} to network",
                from_node_id
            );

            Ok(true)
        } else {
            warn!(
                "❌ [DKG-SECURE] Share verification failed for index {} from {}",
                share_index, from_node_id
            );

            let validation_msg = ShareValidation {
                from: self.id.clone(),
                to: from_node_id.clone(),
                is_valid: false,
            };
            let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
            let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
            self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;

            info!(
                "📡 [DKG-SECURE] Broadcasted ShareValidation (invalid) for {} to network",
                from_node_id
            );

            Ok(false)
        }
    }

    // Debug function to log all current shares
    pub async fn log_all_shares(&self) {
        if !cfg!(debug_assertions) {
            debug!("📊 [DKG] log_all_shares is disabled in release builds");
            return;
        }

        match self.storage.get_all_shares().await {
            Ok(shares) => {
                debug!("📊 [DKG] === CURRENT SHARES DEBUG ===");
                debug!(
                    "📊 [DKG] Node {} has {} shares stored",
                    self.id,
                    shares.len()
                );
                if shares.is_empty() {
                    debug!("📊 [DKG] No shares currently stored");
                } else {
                    for (sender, share) in shares.iter() {
                        debug!(
                            "📊 [DKG] Share from {}: index={} (value redacted)",
                            sender, share.index
                        );
                    }
                }
                debug!("📊 [DKG] === END CURRENT SHARES DEBUG ===");
            }
            Err(e) => {
                warn!("Failed to load shares for logging: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{Database, DatabaseConfig};
    use crate::utils;
    use k256::AffinePoint;
    use tempfile::TempDir;

    /// Helper to create a test database
    fn create_test_db() -> (Database, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = DatabaseConfig {
            path: temp_dir.path().to_str().unwrap().to_string(),
            create_if_missing: true,
            max_open_files: 100,
            encryption_key: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
        };
        let db = Database::new(config).unwrap();
        (db, temp_dir)
    }

    #[tokio::test]
    async fn test_original_commitments_storage() {
        let (db, _temp_dir) = create_test_db();
        let storage = DkgStorage::new(db);

        // Create test commitments
        let commitment1 = AffinePoint::GENERATOR;
        let commitment2 = (ProjectivePoint::GENERATOR * &Scalar::from(2u64)).to_affine();
        let commitments = vec![commitment1, commitment2];

        // Store original commitments
        storage
            .store_original_commitments("node1", &commitments)
            .await
            .unwrap();

        // Retrieve and verify
        let retrieved = storage.get_all_original_commitments().await.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert!(retrieved.contains_key("node1"));
        assert_eq!(retrieved["node1"].len(), 2);
        assert_eq!(retrieved["node1"][0], commitment1);
        assert_eq!(retrieved["node1"][1], commitment2);
    }

    #[tokio::test]
    async fn test_qca_04_validation_deduplication() {
        let (db, _temp_dir) = create_test_db();
        let storage = DkgStorage::new(db);

        // Simulate Node B validating Node A's share
        storage.add_validation("A", "B", true).await.unwrap();

        // Simulate duplicate gossip validation messages from B for A's share
        storage.add_validation("A", "B", true).await.unwrap();
        storage.add_validation("A", "B", true).await.unwrap();

        let validations = storage.get_all_validations().await.unwrap();

        let valid_validations: usize = validations
            .values()
            .map(|v| v.values().filter(|&&valid| valid).count())
            .sum();

        // Should securely deduplicate and only count 1 valid validation
        assert_eq!(valid_validations, 1);

        // Simulate Node B validating Node C's share
        storage.add_validation("C", "B", true).await.unwrap();

        let validations2 = storage.get_all_validations().await.unwrap();
        let count2: usize = validations2
            .values()
            .map(|v| v.values().filter(|&&valid| valid).count())
            .sum();

        // Should be 2 distinct correctly counted validations
        assert_eq!(count2, 2);
    }
}
