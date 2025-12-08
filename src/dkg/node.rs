use anyhow::{anyhow, ensure, Result};
use k256::{ProjectivePoint, Scalar};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::artifacts::{DKGCompletionCallback, DKGStatus};
use crate::database::DkgStorage;
use crate::types::ChannelMessage;

#[derive(Clone)]
struct DKGState {
    status: DKGStatus,
    threshold: usize,
    total_nodes: usize,
    round: u64,
    my_permanent_index: Option<usize>, // Index assigned during initial DKG, never changes
}

pub struct DKGNode {
    pub(super) id: String,
    state: Arc<RwLock<DKGState>>,
    pub(super) storage: DkgStorage,
    pub(super) message_tx: mpsc::Sender<ChannelMessage>,
    pub(super) completion_callback: Option<DKGCompletionCallback>,
    pub(super) chain_code: [u8; 32],
    pub(super) user_intent_manager:
        Option<std::sync::Arc<crate::user_intent_manager::UserIntentManager>>, // optional handle to update users after refresh
}

impl DKGNode {
    pub(crate) fn total_nodes(&self) -> usize {
        self.state.read().unwrap().total_nodes
    }

    pub(crate) fn threshold(&self) -> usize {
        self.state.read().unwrap().threshold
    }

    pub(crate) fn current_round(&self) -> u64 {
        self.state.read().unwrap().round
    }

    pub(crate) fn permanent_index(&self) -> Option<usize> {
        self.state.read().unwrap().my_permanent_index
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

    fn increment_round(&self) {
        self.state.write().unwrap().round += 1;
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
            round: 0,
            my_permanent_index: None,
        };
        Self {
            id,
            state: Arc::new(RwLock::new(state)),
            storage,
            message_tx,
            completion_callback: None,
            chain_code,
            user_intent_manager: None,
        }
    }

    pub fn set_user_intent_manager(
        &mut self,
        registry: std::sync::Arc<crate::user_intent_manager::UserIntentManager>,
    ) {
        self.user_intent_manager = Some(registry);
        info!("🔗 [DKG] User registry handle attached to DKG node");
    }

    /// Load permanent index from storage
    pub async fn load_permanent_index(&mut self) -> Result<()> {
        if let Some(index) = self.storage.get_my_permanent_index().await? {
            self.set_permanent_index(index);
            info!("🔢 [DKG] Loaded permanent index: {}", index);
        }
        Ok(())
    }

    pub async fn reset(&mut self) -> Result<()> {
        let mut failures = Vec::new();

        if let Err(e) = self.storage.clear_shares().await {
            failures.push(format!("clear shares: {e}"));
        }
        if let Err(e) = self.storage.clear_commitments().await {
            failures.push(format!("clear commitments: {e}"));
        }
        if let Err(e) = self.storage.clear_validations().await {
            failures.push(format!("clear validations: {e}"));
        }
        if let Err(e) = self.storage.delete_final_secret().await {
            failures.push(format!("delete final secret: {e}"));
        }
        if let Err(e) = self.storage.delete_final_public().await {
            failures.push(format!("delete final public key: {e}"));
        }
        if let Err(e) = self.storage.delete_vault_tweaked_secret().await {
            failures.push(format!("delete vault tweaked secret: {e}"));
        }
        if let Err(e) = self.storage.delete_vault_group_key().await {
            failures.push(format!("delete vault group key: {e}"));
        }
        if let Err(e) = self.storage.delete_polynomial().await {
            failures.push(format!("delete polynomial: {e}"));
        }

        if failures.is_empty() {
            self.transition_status(DKGStatus::New)?;
            self.increment_round();
            Ok(())
        } else {
            let message = failures.join("; ");
            warn!("Failed to fully reset DKG node {}: {}", self.id, message);
            self.transition_status(DKGStatus::Error {
                kind: format!("reset_failed: {message}"),
            })?;
            Err(anyhow!("Failed to reset DKG node: {}", message))
        }
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

    pub async fn get_vault_tweaked_secret_share(&self) -> Option<Scalar> {
        self.storage
            .get_vault_tweaked_secret()
            .await
            .unwrap_or_default()
    }

    pub async fn get_vault_group_key(&self) -> Option<ProjectivePoint> {
        self.storage.get_vault_group_key().await.unwrap_or_default()
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
        share_value: crate::types::SerializableScalar,
        commitments: Vec<crate::types::SerializablePoint>,
        node_manager: Box<dyn crate::NodeMembership>,
    ) -> Result<bool> {
        use k256::AffinePoint;
        
        info!(
            "🔐 [DKG-SECURE] Processing unicast share index {} from {}",
            share_index, from_node_id
        );

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

        // Verify the share against commitments
        if self.verify_share(&share_value, share_index, &commitments) {
            // Store the share
            let key_share = crate::types::KeyShare {
                index: share_index,
                value: share_value,
            };

            self.storage.store_share(&from_node_id, &key_share).await?;

            // Store commitments
            let raw_commitments: Vec<AffinePoint> =
                commitments.iter().map(|c| c.0).collect();
            self.storage
                .store_commitments(&from_node_id, &raw_commitments)
                .await?;

            // Add validation
            self.storage
                .add_validation(&from_node_id, &self.id, true)
                .await?;

            info!(
                "✅ [DKG-SECURE] Share index {} from {} verified and stored successfully",
                share_index, from_node_id
            );

            // Check if DKG is complete
            self.check_completion(node_manager).await?;

            Ok(true)
        } else {
            warn!(
                "❌ [DKG-SECURE] Share verification failed for index {} from {}",
                share_index, from_node_id
            );
            Ok(false)
        }
    }


    // Test function to verify share generation
    pub fn test_share_generation(&self) -> Result<()> {
        debug!("🧪 Testing share generation for node {}", self.id);

        let polynomial = self.generate_polynomial()?;
        let shares = self.generate_shares(&polynomial)?;

        debug!("🔬 Node {} generated {} shares", self.id, shares.len());
        #[cfg(debug_assertions)]
        {
            debug!(
                "🔬 First share value: {:?}",
                shares.first().map(|s| s.value.0)
            );
            debug!(
                "🔬 Last share value: {:?}",
                shares.last().map(|s| s.value.0)
            );
        }
        #[cfg(not(debug_assertions))]
        {
            debug!("🔬 Share value logging skipped in release builds");
        }

        Ok(())
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
                            "📊 [DKG] Share from {}: index={}, value={:?}",
                            sender, share.index, share.value.0
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
    async fn test_original_commitments_persist_after_refresh() {
        let (db, _temp_dir) = create_test_db();
        let storage = DkgStorage::new(db);

        // Store ORIGINAL commitments
        let original_commitments = vec![AffinePoint::GENERATOR];
        storage
            .store_original_commitments("node1", &original_commitments)
            .await
            .unwrap();

        // Simulate refresh by storing NEW current commitments
        let refresh_commitments =
            vec![(ProjectivePoint::GENERATOR * &Scalar::from(2u64)).to_affine()];
        storage
            .store_commitments("node1", &refresh_commitments)
            .await
            .unwrap();

        // Verify ORIGINAL commitments are UNCHANGED
        let original = storage.get_all_original_commitments().await.unwrap();
        assert_eq!(original["node1"][0], AffinePoint::GENERATOR);

        // Verify CURRENT commitments are UPDATED
        let current = storage.get_all_commitments().await.unwrap();
        assert_ne!(current["node1"][0], AffinePoint::GENERATOR);
        assert_eq!(current["node1"][0], refresh_commitments[0]);
    }

    #[tokio::test]
    async fn test_vault_derivation_from_original_commitments() {
        let (db, _temp_dir) = create_test_db();
        let storage = DkgStorage::new(db);
        let chain_code = [0u8; 32];

        // Create a mock message channel
        let (tx, _rx) = tokio::sync::mpsc::channel(100);

        let adkg = DKGNode::new(
            "test_node".to_string(),
            2,
            4,
            tx,
            storage.clone(),
            chain_code,
        );

        // Store original commitments for 3 nodes
        let c1 = AffinePoint::GENERATOR;
        let c2 = (ProjectivePoint::GENERATOR * &Scalar::from(2u64)).to_affine();
        let c3 = (ProjectivePoint::GENERATOR * &Scalar::from(3u64)).to_affine();

        storage
            .store_original_commitments("node1", &vec![c1])
            .await
            .unwrap();
        storage
            .store_original_commitments("node2", &vec![c2])
            .await
            .unwrap();
        storage
            .store_original_commitments("node3", &vec![c3])
            .await
            .unwrap();

        // Derive vault using original commitments
        let tweak_scalar = Scalar::from(42u64);
        let vault_key1 = adkg
            .derive_vault_group_key_from_original_commitments(tweak_scalar)
            .await
            .unwrap();

        // Store different current commitments (simulating refresh)
        let new_c1 = (ProjectivePoint::GENERATOR * &Scalar::from(10u64)).to_affine();
        let new_c2 = (ProjectivePoint::GENERATOR * &Scalar::from(20u64)).to_affine();
        let new_c3 = (ProjectivePoint::GENERATOR * &Scalar::from(30u64)).to_affine();

        storage
            .store_commitments("node1", &vec![new_c1])
            .await
            .unwrap();
        storage
            .store_commitments("node2", &vec![new_c2])
            .await
            .unwrap();
        storage
            .store_commitments("node3", &vec![new_c3])
            .await
            .unwrap();

        // Derive vault again using original commitments (should be the SAME)
        let vault_key2 = adkg
            .derive_vault_group_key_from_original_commitments(tweak_scalar)
            .await
            .unwrap();

        // Assert vault keys are IDENTICAL
        assert_eq!(
            vault_key1, vault_key2,
            "Vault group key changed after refresh - THIS IS A BUG!"
        );
    }

    #[tokio::test]
    async fn test_vault_addresses_remain_constant_after_refresh() {
        let (db, _temp_dir) = create_test_db();
        let storage = DkgStorage::new(db);
        let chain_code = [0u8; 32];

        // Create a mock message channel
        let (tx, _rx) = tokio::sync::mpsc::channel(100);

        let adkg = DKGNode::new(
            "test_node".to_string(),
            2,
            4,
            tx,
            storage.clone(),
            chain_code,
        );

        // Store original commitments
        let c1 = AffinePoint::GENERATOR;
        let c2 = (ProjectivePoint::GENERATOR * &Scalar::from(2u64)).to_affine();

        storage
            .store_original_commitments("node1", &vec![c1])
            .await
            .unwrap();
        storage
            .store_original_commitments("node2", &vec![c2])
            .await
            .unwrap();

        // Derive vault addresses BEFORE refresh
        let tweak_scalar = Scalar::from(123u64);
        let vault_key_before = adkg
            .derive_vault_group_key_from_original_commitments(tweak_scalar)
            .await
            .unwrap();
        let vault_eth_before = utils::get_eth_address_from_group_key(vault_key_before);
        let vault_btc_before = utils::get_btc_address_from_group_key(vault_key_before);

        // Simulate refresh - update current commitments
        let new_c1 = (ProjectivePoint::GENERATOR * &Scalar::from(100u64)).to_affine();
        let new_c2 = (ProjectivePoint::GENERATOR * &Scalar::from(200u64)).to_affine();

        storage
            .store_commitments("node1", &vec![new_c1])
            .await
            .unwrap();
        storage
            .store_commitments("node2", &vec![new_c2])
            .await
            .unwrap();

        // Derive vault addresses AFTER refresh (from original commitments)
        let vault_key_after = adkg
            .derive_vault_group_key_from_original_commitments(tweak_scalar)
            .await
            .unwrap();
        let vault_eth_after = utils::get_eth_address_from_group_key(vault_key_after);
        let vault_btc_after = utils::get_btc_address_from_group_key(vault_key_after);

        // Assert vault addresses are IDENTICAL
        assert_eq!(
            vault_eth_before, vault_eth_after,
            "Vault ETH address changed after refresh!"
        );
        assert_eq!(
            vault_btc_before, vault_btc_after,
            "Vault BTC address changed after refresh!"
        );

        println!(
            "✅ Vault ETH address remains constant: {}",
            vault_eth_before
        );
        println!(
            "✅ Vault BTC address remains constant: {}",
            vault_btc_before
        );
    }

    #[tokio::test]
    async fn test_multiple_refresh_rounds_preserve_vault() {
        let (db, _temp_dir) = create_test_db();
        let storage = DkgStorage::new(db);
        let chain_code = [0u8; 32];

        // Create a mock message channel
        let (tx, _rx) = tokio::sync::mpsc::channel(100);

        let adkg = DKGNode::new(
            "test_node".to_string(),
            2,
            4,
            tx,
            storage.clone(),
            chain_code,
        );

        // Store original commitments
        storage
            .store_original_commitments("node1", &vec![AffinePoint::GENERATOR])
            .await
            .unwrap();

        let tweak_scalar = Scalar::from(999u64);
        let initial_vault = adkg
            .derive_vault_group_key_from_original_commitments(tweak_scalar)
            .await
            .unwrap();
        let initial_vault_eth = utils::get_eth_address_from_group_key(initial_vault);

        // Simulate 5 refresh rounds
        for round in 1..=5 {
            let new_c =
                (ProjectivePoint::GENERATOR * &Scalar::from((round * 1000) as u64)).to_affine();
            storage
                .store_commitments("node1", &vec![new_c])
                .await
                .unwrap();

            let vault_after_round = adkg
                .derive_vault_group_key_from_original_commitments(tweak_scalar)
                .await
                .unwrap();
            let vault_eth_after_round = utils::get_eth_address_from_group_key(vault_after_round);

            assert_eq!(
                initial_vault_eth, vault_eth_after_round,
                "Vault address changed after refresh round {}!",
                round
            );
        }

        println!("✅ Vault address remained constant through 5 refresh rounds");
    }
}
