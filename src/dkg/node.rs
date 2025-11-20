use crate::utils::hmac_helper::hmac256_from_addr;
use crate::{utils, NodeMembership};
use anyhow::{anyhow, Result};
use ethers::core::k256::ecdsa::Error;
use ff::{Field, PrimeField};
use k256::elliptic_curve::group::Group;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::{any, usize};
use tokio::sync::mpsc;
use tracing::info;
use tracing::warn;

use super::artifacts::{DKGCompletionCallback, DKGMessage, DKGStatus};
use crate::database::DkgStorage;
use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{
    ChannelMessage, GossipsubMessage, KeyShare, SerializablePoint, SerializableScalar,
};

#[derive(Clone)]
pub(super) struct DKGState {
    pub(super) status: DKGStatus,
    pub(super) threshold: usize,
    pub(super) total_nodes: usize,
    pub(super) round: u64,
    pub(super) my_permanent_index: Option<usize>, // Index assigned during initial DKG, never changes
}

pub struct DKGNode {
    pub(super) id: String,
    pub(super) state: Arc<RwLock<DKGState>>,
    pub(super) storage: DkgStorage,
    pub(super) message_tx: mpsc::Sender<ChannelMessage>,
    pub(super) completion_callback: Option<DKGCompletionCallback>,
    pub(super) chain_code: [u8; 32],
    pub(super) user_intent_manager:
        Option<std::sync::Arc<crate::user_intent_manager::UserIntentManager>>, // optional handle to update users after refresh
}

impl DKGNode {
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
            self.state.write().unwrap().my_permanent_index = Some(index);
            info!("🔢 [DKG] Loaded permanent index: {}", index);
        }
        Ok(())
    }

    pub async fn reset(&mut self) {
        if let Err(e) = self.storage.clear_shares().await {
            warn!("Failed to clear shares: {}", e);
        }
        if let Err(e) = self.storage.clear_commitments().await {
            warn!("Failed to clear commitments: {}", e);
        }
        if let Err(e) = self.storage.clear_validations().await {
            warn!("Failed to clear validations: {}", e);
        }
        if let Err(e) = self.storage.delete_final_secret().await {
            warn!("Failed to delete final secret: {}", e);
        }
        if let Err(e) = self.storage.delete_final_public().await {
            warn!("Failed to delete final public key: {}", e);
        }
        if let Err(e) = self.storage.delete_polynomial().await {
            warn!("Failed to delete polynomial: {}", e);
        }

        let mut state = self.state.write().unwrap();
        state.status = DKGStatus::New;
        state.round += 1;
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

    pub fn update_node_params(&mut self, total_nodes: usize, threshold: usize) {
        info!(
            "🔄 Updating DKGNode params: total_nodes = {}, threshold = {}",
            total_nodes, threshold
        );
        let mut state = self.state.write().unwrap();
        state.total_nodes = total_nodes;
        state.threshold = threshold;
    }

    pub async fn get_final_secret_share(&self) -> Option<Scalar> {
        match self.storage.get_final_secret().await {
            Ok(v) => v,
            Err(_) => None,
        }
    }

    pub async fn get_final_public_key(&self) -> Option<ProjectivePoint> {
        match self.storage.get_final_public().await {
            Ok(v) => v,
            Err(_) => None,
        }
    }

    pub async fn get_vault_tweaked_secret_share(&self) -> Option<Scalar> {
        match self.storage.get_vault_tweaked_secret().await {
            Ok(v) => v,
            Err(_) => None,
        }
    }

    pub async fn get_vault_group_key(&self) -> Option<ProjectivePoint> {
        match self.storage.get_vault_group_key().await {
            Ok(v) => v,
            Err(_) => None,
        }
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

    // Test function to verify share generation
    pub fn test_share_generation(&self) -> Result<()> {
        info!("🧪 Testing share generation for node {}", self.id);

        let polynomial = self.generate_polynomial()?;
        let shares = self.generate_shares(&polynomial)?;

        info!("🔬 Node {} generated {} shares", self.id, shares.len());
        info!(
            "🔬 First share value: {:?}",
            shares.first().map(|s| s.value.0)
        );
        info!(
            "🔬 Last share value: {:?}",
            shares.last().map(|s| s.value.0)
        );

        Ok(())
    }

    // Debug function to log all current shares
    pub async fn log_all_shares(&self) {
        match self.storage.get_all_shares().await {
            Ok(shares) => {
                info!("📊 [DKG] === CURRENT SHARES DEBUG ===");
                info!(
                    "📊 [DKG] Node {} has {} shares stored",
                    self.id,
                    shares.len()
                );
                if shares.is_empty() {
                    info!("📊 [DKG] No shares currently stored");
                } else {
                    for (sender, share) in shares.iter() {
                        info!(
                            "📊 [DKG] Share from {}: index={}, value={:?}",
                            sender, share.index, share.value.0
                        );
                    }
                }
                info!("📊 [DKG] === END CURRENT SHARES DEBUG ===");
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
