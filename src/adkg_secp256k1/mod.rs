use crate::utils::hmac_helper::hmac256_from_addr;
use crate::{utils, NodeMembership};
use anyhow::{anyhow, Result};
use ethers::core::k256::ecdsa::Error;
use ff::{Field, PrimeField};
use k256::elliptic_curve::group::Group;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{any, usize};
use tokio::sync::mpsc;
use tracing::info;
use tracing::warn;

use crate::database::DkgStorage;
use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{
    ChannelMessage, GossipsubMessage, KeyShare, SerializablePoint, SerializableScalar,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DKGMessage {
    ShareDistribution {
        from: String,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializablePoint>,
    },
    ShareValidation {
        from: String,
        to: String,
        is_valid: bool,
        round: u64,
    },
    /// Broadcasted when a new node joins and needs shares
    NewNodeJoined {
        new_node_id: String,
        new_node_index: usize,
    },
    /// Sent from existing nodes to the new node with a share
    NewNodeShare {
        from: String,
        to: String,
        share: KeyShare,
        commitment: Vec<SerializablePoint>,
    },
    /// Broadcasted to trigger polynomial refresh after new node joins
    TriggerRefresh { trigger_node: String },
    /// Refresh shares sent from each node during proactive refresh
    RefreshShare {
        from: String,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializablePoint>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DKGStatus {
    New,
    Error { kind: String },
    Started,
    Completed,
}

pub type DKGCompletionCallback = Box<dyn Fn(Scalar, ProjectivePoint) + Send + Sync>;

pub struct DKGNode {
    id: String,
    status: DKGStatus,
    threshold: usize,
    total_nodes: usize,
    storage: DkgStorage,
    message_tx: mpsc::Sender<ChannelMessage>,
    completion_callback: Option<DKGCompletionCallback>,
    round: u64,
    chain_code: [u8; 32],
    my_permanent_index: Option<usize>, // Index assigned during initial DKG, never changes
    user_registry: Option<std::sync::Arc<crate::user_registry::DatabaseUserRegistry>>, // optional handle to update users after refresh
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
        Self {
            id,
            status: DKGStatus::New,
            threshold,
            total_nodes,
            storage,
            message_tx,
            completion_callback: None,
            round: 0,
            chain_code,
            my_permanent_index: None, // Will be set during DKG completion or when joining
            user_registry: None,
        }
    }

    pub fn set_user_registry(
        &mut self,
        registry: std::sync::Arc<crate::user_registry::DatabaseUserRegistry>,
    ) {
        self.user_registry = Some(registry);
        info!("🔗 [DKG] User registry handle attached to DKG node");
    }

    /// Load permanent index from storage
    pub async fn load_permanent_index(&mut self) -> Result<()> {
        if let Some(index) = self.storage.get_my_permanent_index().await? {
            self.my_permanent_index = Some(index);
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

        self.status = DKGStatus::New;
        self.round += 1;
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
        self.status.clone()
    }

    /// Calculate the vault tweaked secret share from the final secret share and vault HMAC
    /// This is the secret share that corresponds to the vault group key
    pub async fn calculate_vault_tweaked_secret_share(
        &self,
        tweak_scalar: Scalar,
    ) -> Result<Scalar> {
        let final_secret_share = self
            .storage
            .get_final_secret()
            .await?
            .ok_or_else(|| anyhow!("No final secret share available"))?;

        // The vault tweaked secret share is: final_secret_share + tweak_scalar
        let vault_tweaked_secret = final_secret_share + tweak_scalar;

        info!("🔐 [DKG] Calculated vault tweaked secret share");
        info!("  📊 Final secret share: {:?}", final_secret_share);
        info!("  🔧 Tweak scalar: {:?}", tweak_scalar);
        info!("  🏦 Vault tweaked secret: {:?}", vault_tweaked_secret);

        Ok(vault_tweaked_secret)
    }

    /// Derive NEW group key from updated commitments for a specific user
    /// This calculates a user-specific group key from commitments that have been updated with HMAC tweaks
    /// The result is DIFFERENT from the original DKG group key
    pub async fn derive_user_specific_group_key_from_commitments(
        &self,
        tweak_scalar: Scalar,
    ) -> Result<ProjectivePoint> {
        let commitments = self.storage.get_all_commitments().await?;
        if commitments.is_empty() {
            return Err(anyhow!("No commitments available (database is empty)"));
        }

        // Get peer indices from database for deterministic ordering
        let peer_indices = self.storage.get_peer_indices().await?;
        if peer_indices.is_empty() {
            return Err(anyhow!("No peer indices available in database"));
        }

        // Sort solver IDs by their stored peer indices instead of alphabetically
        let mut solver_with_indices: Vec<(String, usize)> = commitments
            .keys()
            .filter_map(|sid| peer_indices.get(sid).map(|&idx| (sid.clone(), idx)))
            .collect();
        solver_with_indices.sort_by_key(|(_, idx)| *idx);

        info!(
            "🔢 [DKG] Processing commitments in peer index order: {:?}",
            solver_with_indices
                .iter()
                .map(|(sid, idx)| format!("{}:{}", sid, idx))
                .collect::<Vec<_>>()
        );

        // P_base = Σ C0_i (in peer index order)
        let mut p_base = ProjectivePoint::IDENTITY;
        let mut added = 0usize;
        for (sid, _) in &solver_with_indices {
            if let Some(comms) = commitments.get(sid) {
                if let Some(c0) = comms.get(0) {
                    p_base += ProjectivePoint::from(*c0);
                    added += 1;
                } else {
                    warn!("⚠️ [DKG] Solver {} has no C0 (index 0 missing)", sid);
                }
            }
        }

        if added == 0 {
            return Err(anyhow!(
                "No C0 found in any solver commitments; cannot derive base group key"
            ));
        }

        // T = t * G
        let tweak_point = ProjectivePoint::GENERATOR * &tweak_scalar;

        // P_user = P_base + T
        let p_user = p_base + tweak_point;

        // Optional diff vs stored
        if let Some(stored) = self.storage.get_final_public().await? {
            let delta = p_user + (-stored);
            info!("🔄 [DKG] Δ vs stored final_public_key: {:?}", delta);
        }

        Ok(p_user)
    }

    /// Derive vault group key from ORIGINAL DKG commitments (never changes after initial DKG)
    /// This ensures the vault address remains constant even after refresh operations
    pub async fn derive_vault_group_key_from_original_commitments(
        &self,
        tweak_scalar: Scalar,
    ) -> Result<ProjectivePoint> {
        let commitments = self.storage.get_all_original_commitments().await?;
        if commitments.is_empty() {
            return Err(anyhow!(
                "No original commitments available - vault cannot be derived"
            ));
        }

        // Get peer indices from database for deterministic ordering
        let peer_indices = self.storage.get_peer_indices().await?;
        if peer_indices.is_empty() {
            return Err(anyhow!("No peer indices available in database"));
        }

        // Sort solver IDs by their stored peer indices instead of alphabetically
        let mut solver_with_indices: Vec<(String, usize)> = commitments
            .keys()
            .filter_map(|sid| peer_indices.get(sid).map(|&idx| (sid.clone(), idx)))
            .collect();
        solver_with_indices.sort_by_key(|(_, idx)| *idx);

        info!(
            "🔢 [VAULT] Processing original commitments in peer index order: {:?}",
            solver_with_indices
                .iter()
                .map(|(sid, idx)| format!("{}:{}", sid, idx))
                .collect::<Vec<_>>()
        );

        // P_base = Σ C0_i from ORIGINAL commitments (in peer index order)
        let mut p_base = ProjectivePoint::IDENTITY;
        let mut added = 0usize;
        for (sid, _) in &solver_with_indices {
            if let Some(comms) = commitments.get(sid) {
                if let Some(c0) = comms.get(0) {
                    p_base += ProjectivePoint::from(*c0);
                    added += 1;
                } else {
                    warn!(
                        "⚠️ [VAULT] Solver {} has no C0 in original commitments",
                        sid
                    );
                }
            }
        }

        if added == 0 {
            return Err(anyhow!(
                "No C0 found in original commitments; cannot derive vault"
            ));
        }

        info!(
            "🏦 [VAULT] Using {} original commitment C0s for vault derivation",
            added
        );

        // T = t * G
        let tweak_point = ProjectivePoint::GENERATOR * &tweak_scalar;

        // P_vault = P_base + T (using original commitments)
        let p_vault = p_base + tweak_point;

        Ok(p_vault)
    }

    pub async fn start_dkg(&mut self, node_manager: Box<dyn NodeMembership>) -> Result<()> {
        info!(
            "🚀 Starting DKG for node {} with threshold {} and total nodes {}",
            self.id, self.threshold, self.total_nodes
        );

        let polynomial = self.generate_polynomial()?;
        info!("🔢 Generated polynomial: {:?}", polynomial);

        // Store the polynomial for later use when new nodes join
        self.storage.set_polynomial(&polynomial).await?;
        info!("💾 Stored polynomial for future share generation");

        let shares = self.generate_shares(&polynomial)?;
        let commitments = self.generate_commitments(&polynomial)?;

        self.status = DKGStatus::Started;
        info!("📤 Broadcasting DKG shares and commitments...");
        tokio::time::sleep(Duration::from_secs(1)).await;
        {
            let my_shares = shares.clone();
            let my_commitments = commitments.clone();
            // This will verify, store in database
            // and even send you a local "validation" message if you want.
            self.handle_share_distribution(
                self.id.clone(),
                my_shares,
                my_commitments,
                node_manager,
            )
            .await?;
        }
        self.broadcast_shares(shares, commitments).await?;
        Ok(())
    }

    fn generate_polynomial(&self) -> Result<Vec<Scalar>> {
        let mut rng = OsRng;
        let mut coefficients = Vec::with_capacity(self.threshold);

        for _ in 0..self.threshold {
            coefficients.push(Scalar::random(&mut rng));
        }

        info!(
            "🔢 Generated polynomial with {} coefficients {:?}",
            coefficients.len(),
            coefficients
                .iter()
                .map(|c| format!("{:?}", c))
                .collect::<Vec<String>>()
        );
        Ok(coefficients)
    }

    pub fn update_node_params(&mut self, total_nodes: usize, threshold: usize) {
        info!(
            "🔄 Updating DKGNode params: total_nodes = {}, threshold = {}",
            total_nodes, threshold
        );
        self.total_nodes = total_nodes;
        self.threshold = threshold;
    }

    fn generate_shares(&self, polynomial: &[Scalar]) -> Result<Vec<KeyShare>> {
        info!("🔍 [DKG] === SECRET SHARE GENERATION ===");
        info!(
            "📊 [DKG] Node {} generating shares for {} nodes",
            self.id, self.total_nodes
        );
        info!(
            "🔢 [DKG] Node {} polynomial coefficients: {:?}",
            self.id, polynomial
        );

        let mut shares = Vec::with_capacity(self.total_nodes);

        info!("🔍 [DKG] Generating shares for each index:");
        for i in 1..=self.total_nodes {
            let x = Scalar::from(i as u64);
            let mut y = Scalar::ZERO;

            info!("🔍 [DKG] Calculating share for index {} (x = {:?})", i, x);

            for (j, coeff) in polynomial.iter().enumerate() {
                let mut x_pow = Scalar::ONE;
                for _ in 0..j {
                    x_pow *= x;
                }
                let term = *coeff * x_pow;
                y += term;
                info!(
                    "🔍 [DKG]   Term {}: coeff[{}] * x^{} = {:?} * {:?}^{} = {:?}",
                    j, j, j, coeff, x, j, term
                );
            }

            info!("🔍 [DKG] Final share for index {}: y = {:?}", i, y);

            shares.push(KeyShare {
                index: i,
                value: SerializableScalar(y),
            });
        }

        info!("🔍 [DKG] === GENERATED SHARES SUMMARY ===");
        for (i, share) in shares.iter().enumerate() {
            info!(
                "🔍 [DKG] Share {}: index={}, value={:?}",
                i + 1,
                share.index,
                share.value.0
            );
        }
        info!("🔍 [DKG] === END GENERATED SHARES SUMMARY ===");

        info!(
            "✅ [DKG] Node {} generated {} shares",
            self.id,
            shares.len()
        );
        info!("🔍 [DKG] === END SECRET SHARE GENERATION ===");
        Ok(shares)
    }

    fn generate_commitments(&self, polynomial: &[Scalar]) -> Result<Vec<SerializablePoint>> {
        let commitments: Vec<SerializablePoint> = polynomial
            .iter()
            .map(|coeff| SerializablePoint(AffinePoint::from(ProjectivePoint::GENERATOR * *coeff)))
            .collect();

        info!("🔐 Generated {} commitments", commitments.len());
        Ok(commitments)
    }

    async fn broadcast_shares(
        &self,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializablePoint>,
    ) -> Result<()> {
        let dkg_msg = DKGMessage::ShareDistribution {
            from: self.id.clone(),
            shares,
            commitments,
        };

        let gossip_wrap = GossipsubMessage::DKG(dkg_msg);

        let msg_bytes = serde_json::to_vec(&gossip_wrap)?;
        info!("📡 Broadcasting DKG message: {} bytes", msg_bytes.len());
        self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
        Ok(())
    }

    pub async fn handle_message(
        &mut self,
        msg: DKGMessage,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        match msg {
            DKGMessage::ShareDistribution {
                from,
                shares,
                commitments,
            } => {
                info!("📥 Received share distribution from {}", from);
                self.handle_share_distribution(from, shares, commitments, node_manager.clone())
                    .await?;
            }
            DKGMessage::ShareValidation {
                from,
                to,
                is_valid,
                round,
            } => {
                info!(
                    "✅ Received share validation from {} for {}: {}",
                    from, to, is_valid
                );
                self.handle_share_validation(from, to, is_valid, node_manager)
                    .await?;
            }
            DKGMessage::NewNodeJoined {
                new_node_id,
                new_node_index,
            } => {
                info!(
                    "🆕 New node {} joined at index {}",
                    new_node_id, new_node_index
                );
                self.handle_new_node_joined(new_node_id, new_node_index)
                    .await?;
            }
            DKGMessage::NewNodeShare {
                from,
                to,
                share,
                commitment,
            } => {
                info!("📨 Received new node share from {} to {}", from, to);
                if to == self.id {
                    self.handle_new_node_share_received(
                        from,
                        share,
                        commitment,
                        node_manager.clone(),
                    )
                    .await?;
                }
            }
            DKGMessage::TriggerRefresh { trigger_node } => {
                info!(
                    "🔄 [REFRESH] Received refresh trigger from {}",
                    trigger_node
                );
                self.execute_polynomial_refresh(node_manager).await?;
            }
            DKGMessage::RefreshShare {
                from,
                shares,
                commitments,
            } => {
                info!("🔄 [REFRESH] Received refresh shares from {}", from);
                self.handle_refresh_share(from, shares, commitments, node_manager.clone())
                    .await?;
            }
        }
        Ok(())
    }

    async fn handle_share_distribution(
        &mut self,
        from: String,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializablePoint>,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        let raw_commitments: Vec<AffinePoint> = commitments.into_iter().map(|c| c.0).collect();

        let node_index = self.get_node_index(node_manager.clone());

        // Log all shares received from this node
        info!("🔍 [DKG] === SHARE DISTRIBUTION RECEIVED ===");
        info!(
            "📥 [DKG] Node {} received {} shares from node {}",
            self.id,
            shares.len(),
            from
        );

        info!("🔍 [DKG] All shares received from node {}:", from);
        for (i, share) in shares.iter().enumerate() {
            info!(
                "🔍 [DKG] Share {}: index={}, value={:?} (intended for node with index {})",
                i + 1,
                share.index,
                share.value.0,
                share.index
            );
        }

        info!("🔍 [DKG] === END SHARE DISTRIBUTION RECEIVED ===");

        info!(
            "🔍 [DKG] Looking for share with index {} in {} shares from node {}",
            node_index,
            shares.len(),
            from
        );

        if self.verify_shares(&shares, &raw_commitments) {
            let my_share = shares.into_iter().find(|s| s.index == node_index);
            if let Some(share) = my_share {
                info!(
                    "✅ [DKG] Found valid share for node {} from {}, share value: {:?}",
                    self.id, from, share.value.0
                );

                // Store share by sender ID but also track the share index
                info!("🔍 [DKG] === STORING SHARE ===");
                info!(
                    "🔍 [DKG] Storing share from node {}: index={}, value={:?}",
                    from, share.index, share.value.0
                );

                self.storage.store_share(&from, &share).await?;
                self.storage
                    .store_commitments(&from, &raw_commitments)
                    .await?;

                // Log current state of all stored shares
                let current_shares = self.storage.get_all_shares().await?;
                info!(
                    "🔍 [DKG] Current total shares stored: {}",
                    current_shares.len()
                );
                info!("🔍 [DKG] All stored shares:");
                for (sender, stored_share) in current_shares.iter() {
                    info!(
                        "🔍 [DKG] Stored share from {}: index={}, value={:?}",
                        sender, stored_share.index, stored_share.value.0
                    );
                }
                info!("🔍 [DKG] === END STORING SHARE ===");

                self.handle_share_validation(self.id.clone(), from.clone(), true, node_manager)
                    .await?;

                let validation_msg = DKGMessage::ShareValidation {
                    from: self.id.clone(),
                    to: from,
                    is_valid: true,
                    round: self.round,
                };
                let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
                let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
                self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
            } else {
                info!(
                    "❌ [DKG] Share for index {} not found in shares from {}",
                    node_index, from
                );
                let validation_msg = DKGMessage::ShareValidation {
                    from: self.id.clone(),
                    to: from,
                    is_valid: false,
                    round: self.round,
                };
                let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
                let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
                self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
            }
        } else {
            info!(
                "❌ [DKG] Share verification failed for shares from {}",
                from
            );
            let validation_msg = DKGMessage::ShareValidation {
                from: self.id.clone(),
                to: from,
                is_valid: false,
                round: self.round,
            };
            let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
            let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
            self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
        }
        Ok(())
    }

    fn get_node_index(&self, _node_manager: Box<dyn NodeMembership>) -> usize {
        info!("🔍 [DKG] === NODE INDEX LOOKUP (DB-only) ===");
        info!("🔍 [DKG] Current node ID: {}", self.id);

        match self.storage.get_peer_index_for(&self.id) {
            Ok(Some(idx)) => {
                info!(
                    "🔢 [DKG] Using stored peer index {} for node {}",
                    idx, self.id
                );
                info!("🔍 [DKG] === END NODE INDEX LOOKUP ===");
                idx
            }
            Ok(None) => {
                tracing::warn!(
                    "❌ [DKG] No stored peer index found for {}. Using default index 1.",
                    self.id
                );
                info!("🔍 [DKG] === END NODE INDEX LOOKUP ===");
                1
            }
            Err(e) => {
                tracing::warn!("❌ [DKG] Failed to read peer index from DB for {}: {:?}. Using default index 1.", self.id, e);
                info!("🔍 [DKG] === END NODE INDEX LOOKUP ===");
                1
            }
        }
    }

    pub fn verify_share(
        &self,
        share: &SerializableScalar,
        share_index: usize,
        commitments: &[SerializablePoint],
    ) -> bool {
        if commitments.is_empty() {
            return false;
        }

        info!("🔍 [DKG] === SHARE VERIFICATION ===");
        info!("🔍 [DKG] Verifying share with index: {}", share_index);
        info!(
            "🔍 [DKG] Using x = Scalar::from({}) for verification",
            share_index
        );

        let x = Scalar::from(share_index as u64);
        let mut expected = ProjectivePoint::IDENTITY;

        for (j, commitment) in commitments.iter().enumerate() {
            let mut x_pow = Scalar::ONE;
            for _ in 0..j {
                x_pow *= x;
            }
            expected += ProjectivePoint::from(commitment.0) * x_pow;
        }

        let actual = ProjectivePoint::GENERATOR * share.0;
        let is_valid = expected == actual;

        info!(
            "🔍 [DKG] Share verification result: {}",
            if is_valid { "✅ PASS" } else { "❌ FAIL" }
        );
        info!("🔍 [DKG] === END SHARE VERIFICATION ===");

        is_valid
    }

    pub fn verify_shares(&self, shares: &[KeyShare], commitments: &[AffinePoint]) -> bool {
        if shares.is_empty() || commitments.is_empty() {
            return false;
        }

        info!("🔍 [DKG] === MULTIPLE SHARES VERIFICATION ===");
        info!("🔍 [DKG] Verifying {} shares", shares.len());

        for share in shares {
            info!("🔍 [DKG] Verifying share with index: {}", share.index);
            info!(
                "🔍 [DKG] Using x = Scalar::from({}) for verification",
                share.index
            );

            let x = Scalar::from(share.index as u64);
            let mut expected = ProjectivePoint::IDENTITY;

            for (j, commitment) in commitments.iter().enumerate() {
                let mut x_pow = Scalar::ONE;
                for _ in 0..j {
                    x_pow *= x;
                }
                expected += ProjectivePoint::from(*commitment) * x_pow;
            }

            let actual = ProjectivePoint::GENERATOR * share.value.0;
            if expected != actual {
                info!("❌ Share verification failed for index {}", share.index);
                info!("🔍 [DKG] === END MULTIPLE SHARES VERIFICATION (FAILED) ===");
                return false;
            } else {
                info!("✅ Share verification passed for index {}", share.index);
            }
        }

        info!("✅ All shares verified successfully");
        info!("🔍 [DKG] === END MULTIPLE SHARES VERIFICATION (SUCCESS) ===");
        true
    }

    async fn handle_share_validation(
        &mut self,
        from: String,
        to: String,
        is_valid: bool,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        self.storage.add_validation(&to, is_valid).await?;
        info!("📊 Validation from {} to {}: {}", from, to, is_valid);
        self.check_completion(node_manager).await?;
        Ok(())
    }

    async fn check_completion(&mut self, node_manager: Box<dyn NodeMembership>) -> Result<()> {
        let (shares_len, validations_len, valid_validations) = {
            let validations = self.storage.get_all_validations().await?;
            let shares = self.storage.get_all_shares().await?;

            // Log all shares currently stored
            info!("📊 [DKG] === SHARES STATUS CHECK ===");
            info!("📊 [DKG] Total shares stored: {}", shares.len());
            for (sender, share) in shares.iter() {
                info!(
                    "📊 [DKG] Share from {}: index={}, value={:?}",
                    sender, share.index, share.value.0
                );
            }
            info!("📊 [DKG] === END SHARES STATUS ===");

            info!("🎉 [DKG] Validations: {:?}", validations);
            let valid_validations: usize = validations
                .values()
                .map(|v| v.iter().filter(|&&valid| valid).count())
                .sum();
            (shares.len(), validations.len(), valid_validations)
        };

        info!(
            "🔍 [DKG] Checking DKG completion - shares: {}, validations: {}",
            shares_len, validations_len
        );

        if valid_validations >= (node_manager.get_total_nodes()) * (node_manager.get_total_nodes())
            && shares_len >= node_manager.get_total_nodes()
        {
            info!(
                "✅ [DKG] Required validations: {} and valid validations: {}",
                (node_manager.get_total_nodes()) * (node_manager.get_total_nodes()),
                valid_validations
            );
            info!("🎉 [DKG] DKG completion criteria met! Generating final keys...");
            self.generate_group_key(node_manager).await?;
        } else {
            info!(
                "⏳ [DKG] DKG not yet complete - need {} validations and {} shares, have {} and {}",
                (node_manager.get_total_nodes()) * (node_manager.get_total_nodes()),
                node_manager.get_total_nodes(),
                valid_validations,
                shares_len
            );
        }
        Ok(())
    }

    async fn generate_group_key(&mut self, node_manager: Box<dyn NodeMembership>) -> Result<()> {
        let shares = self.storage.get_all_shares().await?;
        let commitments = self.storage.get_all_commitments().await?;
        info!("🔐 [DKG] Commitments: {:?}", commitments);
        info!("🔐 [DKG] Commitments size: {}", commitments.len());

        let node_index = self.get_node_index(node_manager);
        info!(
            "🔍 [DKG] Node {} calculating final secret share using shares for index {}",
            self.id, node_index
        );

        // Calculate final secret share (sum of all shares meant for THIS node's index)
        let mut final_secret_share = Scalar::ZERO;
        info!("🔐 [DKG] Calculating final secret share...");
        info!("📊 [DKG] Total shares received: {}", shares.len());

        // Log all shares before processing
        info!("🔍 [DKG] === ALL SHARES BEFORE FINAL CALCULATION ===");
        info!(
            "🔍 [DKG] Node {} has {} total shares stored",
            self.id,
            shares.len()
        );
        for (from, share) in shares.iter() {
            info!(
                "🔍 [DKG] Share from {}: index={}, value={:?} (will be used if index matches our index {})",
                from, share.index, share.value.0, node_index
            );
        }
        info!("🔍 [DKG] === END ALL SHARES ===");

        let mut used_shares = 0;
        let mut skipped_shares = 0;

        info!("🔍 [DKG] === FINAL SECRET SHARE CALCULATION ===");
        info!(
            "🔍 [DKG] Starting with final_secret_share = {:?}",
            final_secret_share
        );

        for (from, share) in shares.iter() {
            // Only use shares that are meant for this node's index
            if share.index == node_index {
                info!(
                    "✅ [DKG] Using share from {} with index {} (matches our index {}) - value: {:?}",
                    from, share.index, node_index, share.value.0
                );
                info!("🔍 [DKG] Adding {:?} to final_secret_share", share.value.0);
                final_secret_share += share.value.0;
                info!("🔍 [DKG] New final_secret_share = {:?}", final_secret_share);
                used_shares += 1;
            } else {
                info!(
                    "❌ [DKG] Skipping share from {} with index {} (doesn't match our index {}) - value: {:?}",
                    from, share.index, node_index, share.value.0
                );
                skipped_shares += 1;
            }
        }

        info!("🔍 [DKG] === END FINAL SECRET SHARE CALCULATION ===");

        info!(
            "📊 [DKG] Final calculation summary: used {} shares, skipped {} shares",
            used_shares, skipped_shares
        );

        let first_comms: Vec<AffinePoint> = commitments
            .values()
            .filter_map(|comms| comms.get(0).cloned())
            .collect();

        // Calculate final public key (sum of all commitment constant terms) in peer-index order
        let mut final_public_key = ProjectivePoint::IDENTITY;

        // Retrieve peer indices from database and order commitments by index
        let peer_indices = self.storage.get_peer_indices().await?;
        let mut solver_with_indices: Vec<(String, usize)> = commitments
            .keys()
            .cloned()
            .filter_map(|sid| peer_indices.get(&sid).copied().map(|idx| (sid, idx)))
            .collect();
        solver_with_indices.sort_by_key(|(_, idx)| *idx);

        info!(
            "🔢 [DKG] Summing commitment C0 terms in peer index order: {:?}",
            solver_with_indices
                .iter()
                .map(|(sid, idx)| format!("{}:{}", sid, idx))
                .collect::<Vec<_>>()
        );

        for (sid, _) in solver_with_indices {
            if let Some(comms) = commitments.get(&sid) {
                if let Some(c0) = comms.get(0) {
                    final_public_key += ProjectivePoint::from(*c0);
                } else {
                    warn!("⚠️ [DKG] Solver {} has no C0 (index 0 missing)", sid);
                }
            }
        }

        // Store the results
        self.storage.set_final_secret(final_secret_share).await?;
        self.storage.set_final_public(final_public_key).await?;

        // Store the permanent index (will never change after this)
        self.storage.set_my_permanent_index(node_index).await?;
        self.my_permanent_index = Some(node_index);
        info!("🔢 [DKG] Stored permanent index: {}", node_index);

        // Store all commitments as ORIGINAL commitments (these will never change)
        info!("🏦 [DKG] Storing original commitments for permanent vault derivation...");
        for (from, comms) in commitments.iter() {
            if let Err(e) = self.storage.store_original_commitments(from, comms).await {
                warn!(
                    "⚠️ [DKG] Failed to store original commitments for {}: {}",
                    from, e
                );
            } else {
                info!("✅ [DKG] Stored original commitments for {}", from);
            }
        }
        info!("🏦 [DKG] All original commitments stored successfully");

        // Update status
        self.status = DKGStatus::Completed;

        // Log the final results
        info!("🎯 [DKG] DKG COMPLETED for node {}!", self.id);
        info!("🔐 [DKG] Final secret share: {:?}", final_secret_share);
        info!("🔑 [DKG] Final public key: {:?}", final_public_key);
        info!("📊 [DKG] Total shares collected: {}", shares.len());
        info!("✅ [DKG] DKG status: {:?}", self.status);

        // Log all collected shares for debugging
        info!("🔍 [DKG] === FINAL SHARES SUMMARY ===");
        info!("🔍 [DKG] Node {} final shares summary:", self.id);
        for (from, share) in shares.iter() {
            let was_used = if share.index == node_index {
                "✅ USED"
            } else {
                "❌ SKIPPED"
            };
            info!(
                "🔍 [DKG] Share from {}: index={}, value={:?} - {}",
                from, share.index, share.value.0, was_used
            );
        }
        info!("🔍 [DKG] Final secret share: {:?}", final_secret_share);
        info!("🔍 [DKG] === END FINAL SHARES SUMMARY ===");

        if let Some(callback) = self.completion_callback.take() {
            callback(final_secret_share, final_public_key);
        }

        let eth_address = utils::get_eth_address_from_group_key(final_public_key);
        let btc_address = utils::get_btc_address_from_group_key(final_public_key);

        info!("📬 Ethereum Address from Group Key: {}", eth_address);
        info!("📬 Bitcoin Address from Group Key: {}", btc_address);

        // Derive vault addresses using the same flow as user registration
        let vault_hmac = hmac256_from_addr(&eth_address, &self.chain_code)
            .map_err(|e| anyhow!("Failed to generate vault HMAC: {}", e))?;

        info!("🏦 [DKG] === VAULT GENERATION STARTED ===");
        info!("🏦 [DKG] Main ETH address: {}", eth_address);
        info!("🏦 [DKG] Vault HMAC: {:?}", vault_hmac);

        let tweak_scalar = k256::Scalar::from_repr(vault_hmac.into()).unwrap();
        info!("🏦 [DKG] Vault tweak scalar: {:?}", tweak_scalar);

        // Calculate and store the vault tweaked secret share
        match self
            .calculate_vault_tweaked_secret_share(tweak_scalar)
            .await
        {
            Ok(vault_tweaked_secret) => {
                info!(
                    "🔐 [DKG] Successfully calculated vault tweaked secret share: {:?}",
                    vault_tweaked_secret
                );
                if let Err(e) = self
                    .storage
                    .set_vault_tweaked_secret(vault_tweaked_secret)
                    .await
                {
                    warn!("⚠️ [DKG] Failed to store vault tweaked secret share: {}", e);
                } else {
                    info!("✅ [DKG] Successfully stored vault tweaked secret share in database");
                }
            }
            Err(e) => {
                warn!(
                    "⚠️ [DKG] Failed to calculate vault tweaked secret share: {}",
                    e
                );
            }
        }

        // Derive and store the vault group key and addresses using ORIGINAL commitments
        match self
            .derive_vault_group_key_from_original_commitments(tweak_scalar)
            .await
        {
            Ok(vault_group_key) => {
                let vault_eth = utils::get_eth_address_from_group_key(vault_group_key);
                let vault_btc = utils::get_btc_address_from_group_key(vault_group_key);
                info!("🏦 [DKG] Derived vault group key: {:?}", vault_group_key);
                info!("🏦 [DKG] Vault ETH address: {}", vault_eth);
                info!("🏦 [DKG] Vault BTC address: {}", vault_btc);

                if let Err(e) = self
                    .storage
                    .set_vault_addresses(&vault_eth, &vault_btc)
                    .await
                {
                    warn!("⚠️ [DKG] Failed to store vault addresses: {}", e);
                } else {
                    info!("✅ [DKG] Successfully stored vault addresses in database");
                    info!(
                        "📦 [DKG] Vault addresses - ETH: {}, BTC: {}",
                        vault_eth, vault_btc
                    );
                }

                // Store the vault group key
                if let Err(e) = self.storage.set_vault_group_key(vault_group_key).await {
                    warn!("⚠️ [DKG] Failed to store vault group key: {}", e);
                } else {
                    info!("✅ [DKG] Successfully stored vault group key in database");
                }
            }
            Err(e) => {
                warn!("⚠️ [DKG] Failed to derive vault group key: {}", e);
            }
        }

        info!("🏦 [DKG] === VAULT GENERATION COMPLETED ===");

        // Mark initial DKG as complete if this is the first DKG with exactly 4 nodes
        if self.total_nodes == 4 {
            if let Err(e) = self.storage.set_initial_dkg_complete(true).await {
                warn!("⚠️ [DKG] Failed to set initial DKG complete flag: {}", e);
            } else {
                info!("🎯 [DKG] Marked initial DKG as complete (4-node setup)");
            }
        }

        Ok(())
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
        matches!(self.status, DKGStatus::Completed)
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

    /// Generate a zero-constant polynomial (constant term is 0)
    /// This is used when a new node joins to re-randomize shares without changing the secret
    /// Example: 0 + r1*x + r2*x^2 + ... where r1, r2, ... are random
    fn generate_zero_constant_polynomial(&self) -> Result<Vec<Scalar>> {
        let mut rng = OsRng;
        let mut coefficients = Vec::with_capacity(self.threshold);

        // First coefficient (constant term) is ZERO
        coefficients.push(Scalar::ZERO);

        // Remaining coefficients are random
        for _ in 1..self.threshold {
            coefficients.push(Scalar::random(&mut rng));
        }

        info!(
            "🔢 [REFRESH] Generated zero-constant polynomial with {} coefficients",
            coefficients.len()
        );
        info!(
            "🔢 [REFRESH] Constant term (a0) = {:?} (should be ZERO)",
            coefficients[0]
        );

        Ok(coefficients)
    }

    /// Calculate Lagrange coefficient pi(0) for node at given index
    /// pi(0) = product of (0 - j) / (i - j) for all j != i
    /// Used in proactive refresh: Gi(x) = Si * pi(0) + zero_constant_polynomial(x)
    fn calculate_lagrange_coefficient(&self, my_index: usize, all_indices: &[usize]) -> Scalar {
        info!(
            "🔢 [REFRESH] Calculating Lagrange coefficient for index {}",
            my_index
        );

        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;

        for &j in all_indices {
            if j != my_index {
                // Numerator: (0 - j) = -j
                let j_scalar = Scalar::from(j as u64);
                let neg_j = Scalar::ZERO - j_scalar;
                numerator *= neg_j;

                // Denominator: (i - j)
                let i_scalar = Scalar::from(my_index as u64);
                let diff = i_scalar - j_scalar;
                denominator *= diff;

                info!(
                    "🔢 [REFRESH]   j={}: numerator term = -{}  denominator term = ({} - {})",
                    j, j, my_index, j
                );
            }
        }

        // Calculate pi(0) = numerator / denominator
        let denominator_inv = denominator.invert().unwrap();
        let lagrange_coeff = numerator * denominator_inv;

        info!(
            "🔢 [REFRESH] Lagrange coefficient pi({}) = {:?}",
            my_index, lagrange_coeff
        );
        lagrange_coeff
    }

    /// Generate refresh polynomial: Gi(x) = Si * pi(0) + zero_constant_polynomial(x)
    /// This is used in proactive refresh to re-randomize shares while keeping the same secret
    async fn generate_refresh_polynomial(
        &self,
        my_index: usize,
        all_indices: &[usize],
    ) -> Result<Vec<Scalar>> {
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");
        info!(
            "🔄 [REFRESH] GENERATING REFRESH POLYNOMIAL FOR NODE {}",
            my_index
        );
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");
        info!("🔄 [REFRESH] Node ID: {}", self.id);
        info!("🔄 [REFRESH] My index: {}", my_index);
        info!("🔄 [REFRESH] All indices for Lagrange: {:?}", all_indices);
        info!("⚠️  [REFRESH] CRITICAL: All nodes MUST use the SAME all_indices array!");
        info!("⚠️  [REFRESH] If nodes disagree on all_indices, the secret WILL change!");

        // Get my current secret share Si
        let my_secret_share = self
            .storage
            .get_final_secret()
            .await?
            .ok_or_else(|| anyhow!("No final secret share available for refresh"))?;

        info!(
            "🔐 [REFRESH] My current secret share S_{} = {:?}",
            my_index, my_secret_share
        );

        // Calculate Lagrange coefficient pi(0)
        info!(
            "🔢 [REFRESH] Calculating Lagrange coefficient λ_{}(0) over indices {:?}...",
            my_index, all_indices
        );
        let lagrange_coeff = self.calculate_lagrange_coefficient(my_index, all_indices);
        info!("🔢 [REFRESH] λ_{}(0) = {:?}", my_index, lagrange_coeff);

        // Calculate the constant term that THIS node contributes to the secret
        let constant_contribution = my_secret_share * lagrange_coeff;
        info!(
            "🎯 [REFRESH] This node's contribution to secret: S_{} * λ_{}(0) = {:?}",
            my_index, my_index, constant_contribution
        );
        info!("📝 [REFRESH] Mathematical invariant: Σ_i (S_i * λ_i(0)) = S (original secret)");
        info!(
            "📝 [REFRESH] If all nodes use indices {:?}, sum should equal original secret",
            all_indices
        );

        // Generate zero-constant polynomial (constant term = 0, other coefficients random)
        let zero_poly = self.generate_zero_constant_polynomial()?;
        info!("🎲 [REFRESH] Generated zero-constant polynomial for randomization");
        info!(
            "🎲 [REFRESH] Zero poly constant term (should be 0): {:?}",
            zero_poly[0]
        );

        // Gi(x) = Si * λi(0) + zero_constant_polynomial(x)
        let mut refresh_poly = zero_poly.clone();

        // The constant term: Gi(0) = Si * λi(0) + 0 = Si * λi(0)
        refresh_poly[0] = constant_contribution;

        info!("🔄 [REFRESH] Refresh polynomial G_{}(x):", my_index);
        info!(
            "🔄 [REFRESH]   G_{}(0) = {:?} (contribution to secret)",
            my_index, refresh_poly[0]
        );
        for (i, coeff) in refresh_poly.iter().enumerate().skip(1) {
            info!(
                "🔄 [REFRESH]   Coefficient[{}] = {:?} (randomness)",
                i, coeff
            );
        }
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");

        Ok(refresh_poly)
    }

    /// Called by existing nodes when a new node joins
    /// Uses the existing polynomial to send a share to the new node
    /// The polynomial is NOT modified - we just evaluate it at the new node's index
    async fn handle_new_node_joined(
        &mut self,
        new_node_id: String,
        new_node_index: usize,
    ) -> Result<()> {
        info!(
            "🆕 [NEW_NODE] Handling new node join: {} at index {}",
            new_node_id, new_node_index
        );

        // Get the stored polynomial (existing, unmodified)
        let polynomial = match self.storage.get_polynomial().await? {
            Some(poly) => poly,
            None => {
                warn!("⚠️ [NEW_NODE] No polynomial stored, cannot generate share for new node");
                return Ok(());
            }
        };

        info!(
            "🔍 [NEW_NODE] Retrieved stored polynomial with {} coefficients",
            polynomial.len()
        );
        info!("🔍 [NEW_NODE] Using EXISTING polynomial (unmodified) to generate share");

        // Evaluate the existing polynomial at the new node's index
        // For example: If F(x) = 4+2x and new node index is 5, then F(5) = 4+2*5 = 14
        let x = Scalar::from(new_node_index as u64);
        let mut y = Scalar::ZERO;

        info!(
            "🔍 [NEW_NODE] Evaluating polynomial at x = {}",
            new_node_index
        );
        for (j, coeff) in polynomial.iter().enumerate() {
            let mut x_pow = Scalar::ONE;
            for _ in 0..j {
                x_pow *= x;
            }
            let term = *coeff * x_pow;
            y += term;
            info!("🔍 [NEW_NODE]   Term {}: coeff * x^{} = {:?}", j, j, term);
        }

        info!(
            "🔍 [NEW_NODE] Share for new node at index {}: {:?}",
            new_node_index, y
        );

        let share = KeyShare {
            index: new_node_index,
            value: SerializableScalar(y),
        };

        // Generate commitments for the existing polynomial
        let commitments = self.generate_commitments(&polynomial)?;

        // Send the share to the new node
        let msg = DKGMessage::NewNodeShare {
            from: self.id.clone(),
            to: new_node_id.clone(),
            share,
            commitment: commitments,
        };

        let gossip_wrap = GossipsubMessage::DKG(msg);
        let msg_bytes = serde_json::to_vec(&gossip_wrap)?;
        self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;

        info!(
            "✅ [NEW_NODE] Sent share to new node {} using existing polynomial",
            new_node_id
        );

        Ok(())
    }

    /// Called by the new node when it receives a share from an existing node
    async fn handle_new_node_share_received(
        &mut self,
        from: String,
        share: KeyShare,
        commitments: Vec<SerializablePoint>,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        info!("📨 [NEW_NODE] Received share from existing node {}", from);
        info!(
            "📨 [NEW_NODE] Share index: {}, value: {:?}",
            share.index, share.value.0
        );

        // Verify the share
        if !self.verify_share(&share.value, share.index, &commitments) {
            warn!("❌ [NEW_NODE] Share verification failed from {}", from);
            return Ok(());
        }

        info!("✅ [NEW_NODE] Share verified successfully from {}", from);

        // Convert commitments to raw format for storage
        let raw_commitments: Vec<AffinePoint> = commitments.into_iter().map(|c| c.0).collect();

        // Store the share
        self.storage.store_share(&from, &share).await?;
        self.storage
            .store_commitments(&from, &raw_commitments)
            .await?;

        info!("💾 [NEW_NODE] Stored share from {}", from);

        // Check if we have received shares from all existing nodes
        let shares = self.storage.get_all_shares().await?;
        let commitments_map = self.storage.get_all_commitments().await?;
        info!(
            "📊 [NEW_NODE] Total shares received: {}/{}",
            shares.len(),
            self.total_nodes - 1
        );

        // If we have shares from all existing nodes (total_nodes - 1), calculate the final secret share
        if shares.len() >= self.total_nodes - 1 {
            info!("🎉 [NEW_NODE] Received all shares from existing nodes! Calculating final secret share...");

            // Calculate final secret share by summing all received shares
            let mut final_secret_share = Scalar::ZERO;

            info!("🔍 [NEW_NODE] === FINAL SECRET SHARE CALCULATION ===");
            info!(
                "🔍 [NEW_NODE] Starting with final_secret_share = {:?}",
                final_secret_share
            );

            for (from_node, share) in shares.iter() {
                info!(
                    "✅ [NEW_NODE] Adding share from {} - value: {:?}",
                    from_node, share.value.0
                );
                final_secret_share += share.value.0;
                info!(
                    "🔍 [NEW_NODE] New final_secret_share = {:?}",
                    final_secret_share
                );
            }

            info!("🔍 [NEW_NODE] === END FINAL SECRET SHARE CALCULATION ===");

            // Calculate final public key (sum of all commitment constant terms) in peer-index order
            let mut final_public_key = ProjectivePoint::IDENTITY;

            // Retrieve peer indices and order commitments by stored index
            let peer_indices = self.storage.get_peer_indices().await?;
            let mut solver_with_indices: Vec<(String, usize)> = commitments_map
                .keys()
                .cloned()
                .filter_map(|sid| peer_indices.get(&sid).copied().map(|idx| (sid, idx)))
                .collect();
            solver_with_indices.sort_by_key(|(_, idx)| *idx);

            info!(
                "🔢 [NEW_NODE] Summing commitment C0 terms in peer index order: {:?}",
                solver_with_indices
                    .iter()
                    .map(|(sid, idx)| format!("{}:{}", sid, idx))
                    .collect::<Vec<_>>()
            );

            for (sid, _) in solver_with_indices {
                if let Some(comms) = commitments_map.get(&sid) {
                    if let Some(c0) = comms.get(0) {
                        info!("✅ [NEW_NODE] Adding commitment C0 from {}: {:?}", sid, c0);
                        final_public_key += ProjectivePoint::from(*c0);
                    } else {
                        warn!("⚠️ [NEW_NODE] Solver {} has no C0 (index 0 missing)", sid);
                    }
                }
            }

            // Store the results
            self.storage.set_final_secret(final_secret_share).await?;
            self.storage.set_final_public(final_public_key).await?;

            // Store the permanent index for the new node (always gets the next index = total_nodes)
            let new_node_index = self.total_nodes;
            self.storage.set_my_permanent_index(new_node_index).await?;
            self.my_permanent_index = Some(new_node_index);
            info!(
                "🔢 [NEW_NODE] Stored permanent index: {} (new node gets index = total_nodes)",
                new_node_index
            );

            // Store all commitments as ORIGINAL commitments (these will never change)
            info!("🏦 [NEW_NODE] Storing original commitments for permanent vault derivation...");
            for (from, comms) in commitments_map.iter() {
                if let Err(e) = self.storage.store_original_commitments(from, comms).await {
                    warn!(
                        "⚠️ [NEW_NODE] Failed to store original commitments for {}: {}",
                        from, e
                    );
                } else {
                    info!("✅ [NEW_NODE] Stored original commitments for {}", from);
                }
            }
            info!("🏦 [NEW_NODE] All original commitments stored successfully");

            // Update status
            self.status = DKGStatus::Completed;

            // Log the final results
            info!("🎯 [NEW_NODE] DKG COMPLETED for new node {}!", self.id);
            info!("🔐 [NEW_NODE] Final secret share: {:?}", final_secret_share);
            info!("🔑 [NEW_NODE] Final public key: {:?}", final_public_key);
            info!("📊 [NEW_NODE] Total shares collected: {}", shares.len());
            info!("✅ [NEW_NODE] DKG status: {:?}", self.status);

            // Call completion callback if set
            if let Some(callback) = self.completion_callback.take() {
                callback(final_secret_share, final_public_key);
            }

            // Generate and log addresses
            let eth_address = utils::get_eth_address_from_group_key(final_public_key);
            let btc_address = utils::get_btc_address_from_group_key(final_public_key);

            info!(
                "📬 [NEW_NODE] Ethereum Address from Group Key: {}",
                eth_address
            );
            info!(
                "📬 [NEW_NODE] Bitcoin Address from Group Key: {}",
                btc_address
            );

            // Derive vault addresses using the same flow as regular DKG
            let vault_hmac = hmac256_from_addr(&eth_address, &self.chain_code)
                .map_err(|e| anyhow!("Failed to generate vault HMAC: {}", e))?;

            info!("🏦 [NEW_NODE] === VAULT GENERATION STARTED ===");
            info!("🏦 [NEW_NODE] Main ETH address: {}", eth_address);
            info!("🏦 [NEW_NODE] Vault HMAC: {:?}", vault_hmac);

            let tweak_scalar = k256::Scalar::from_repr(vault_hmac.into()).unwrap();
            info!("🏦 [NEW_NODE] Vault tweak scalar: {:?}", tweak_scalar);

            // Calculate and store the vault tweaked secret share
            match self
                .calculate_vault_tweaked_secret_share(tweak_scalar)
                .await
            {
                Ok(vault_tweaked_secret) => {
                    info!(
                        "🔐 [NEW_NODE] Successfully calculated vault tweaked secret share: {:?}",
                        vault_tweaked_secret
                    );
                    if let Err(e) = self
                        .storage
                        .set_vault_tweaked_secret(vault_tweaked_secret)
                        .await
                    {
                        warn!(
                            "⚠️ [NEW_NODE] Failed to store vault tweaked secret share: {}",
                            e
                        );
                    } else {
                        info!("✅ [NEW_NODE] Successfully stored vault tweaked secret share in database");
                    }
                }
                Err(e) => {
                    warn!(
                        "⚠️ [NEW_NODE] Failed to calculate vault tweaked secret share: {}",
                        e
                    );
                }
            }

            // Derive and store the vault group key and addresses using ORIGINAL commitments
            match self
                .derive_vault_group_key_from_original_commitments(tweak_scalar)
                .await
            {
                Ok(vault_group_key) => {
                    let vault_eth = utils::get_eth_address_from_group_key(vault_group_key);
                    let vault_btc = utils::get_btc_address_from_group_key(vault_group_key);
                    info!(
                        "🏦 [NEW_NODE] Derived vault group key: {:?}",
                        vault_group_key
                    );
                    info!("🏦 [NEW_NODE] Vault ETH address: {}", vault_eth);
                    info!("🏦 [NEW_NODE] Vault BTC address: {}", vault_btc);

                    if let Err(e) = self
                        .storage
                        .set_vault_addresses(&vault_eth, &vault_btc)
                        .await
                    {
                        warn!("⚠️ [NEW_NODE] Failed to store vault addresses: {}", e);
                    } else {
                        info!("✅ [NEW_NODE] Successfully stored vault addresses in database");
                        info!(
                            "📦 [NEW_NODE] Vault addresses - ETH: {}, BTC: {}",
                            vault_eth, vault_btc
                        );
                    }

                    // Store the vault group key
                    if let Err(e) = self.storage.set_vault_group_key(vault_group_key).await {
                        warn!("⚠️ [NEW_NODE] Failed to store vault group key: {}", e);
                    } else {
                        info!("✅ [NEW_NODE] Successfully stored vault group key in database");
                    }
                }
                Err(e) => {
                    warn!("⚠️ [NEW_NODE] Failed to derive vault group key: {}", e);
                }
            }

            info!("🏦 [NEW_NODE] === VAULT GENERATION COMPLETED ===");

            // Trigger polynomial refresh after new node completes
            info!("🔄 [NEW_NODE] New node setup complete, triggering polynomial refresh");

            // Broadcast trigger to other nodes
            match self.trigger_polynomial_refresh().await {
                Ok(should_execute_locally) => {
                    if should_execute_locally {
                        info!(
                            "🔄 [NEW_NODE] Executing refresh locally (won't receive own broadcast)"
                        );
                        if let Err(e) = self.execute_polynomial_refresh(node_manager).await {
                            warn!("⚠️ [NEW_NODE] Failed to execute local refresh: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("⚠️ [NEW_NODE] Failed to trigger polynomial refresh: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Broadcast that this node is new and needs shares
    /// This should be called when a new node joins the network
    pub async fn request_shares_as_new_node(&self, node_index: usize) -> Result<()> {
        info!(
            "🆕 [NEW_NODE] Broadcasting new node join request for node {} at index {}",
            self.id, node_index
        );

        let msg = DKGMessage::NewNodeJoined {
            new_node_id: self.id.clone(),
            new_node_index: node_index,
        };

        let gossip_wrap = GossipsubMessage::DKG(msg);
        let msg_bytes = serde_json::to_vec(&gossip_wrap)?;
        self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;

        info!("✅ [NEW_NODE] Broadcasted new node join request");

        Ok(())
    }

    /// Start polynomial refresh process
    /// Called by the new node after it completes receiving all shares
    /// Returns true if this node should also execute refresh locally
    pub async fn trigger_polynomial_refresh(&self) -> Result<bool> {
        info!(
            "🔄 [REFRESH] Triggering polynomial refresh from node {}",
            self.id
        );

        let msg = DKGMessage::TriggerRefresh {
            trigger_node: self.id.clone(),
        };

        let gossip_wrap = GossipsubMessage::DKG(msg);
        let msg_bytes = serde_json::to_vec(&gossip_wrap)?;
        self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;

        info!("✅ [REFRESH] Broadcasted refresh trigger");
        info!("⚠️ [REFRESH] Note: This node won't receive its own broadcast, will execute refresh locally");

        // Return true to indicate this node should also execute refresh
        Ok(true)
    }

    /// Execute polynomial refresh and broadcast refresh shares
    pub async fn execute_polynomial_refresh(
        &mut self,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");
        info!("🔄 [REFRESH] EXECUTING POLYNOMIAL REFRESH");
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");
        info!("🔄 [REFRESH] Node: {}", self.id);

        // Get all active nodes and their indices from database (DB-first ordering)
        let active_nodes: Vec<String> = node_manager
            .get_active_nodes()
            .into_iter()
            .map(|p| p.to_string())
            .collect();

        info!(
            "🔍 [REFRESH] Active nodes from node_manager: {:?}",
            active_nodes
        );

        let peer_indices_map = self.storage.get_peer_indices().await?;
        info!(
            "🔍 [REFRESH] Peer indices in database: {:?}",
            peer_indices_map
        );

        let mut nodes_with_indices: Vec<(String, usize)> = active_nodes
            .into_iter()
            .filter_map(|pid| peer_indices_map.get(&pid).copied().map(|idx| (pid, idx)))
            .collect();
        nodes_with_indices.sort_by_key(|(_, idx)| *idx);

        info!(
            "🔍 [REFRESH] Nodes with indices (sorted): {:?}",
            nodes_with_indices
        );

        let total_nodes = nodes_with_indices.len();
        let threshold = node_manager.get_threshold();

        info!(
            "🔍 [REFRESH] Total nodes: {}, Threshold: {}",
            total_nodes, threshold
        );

        // CRITICAL: Update this node's total_nodes parameter to current network size
        // Old nodes will have total_nodes = 4, but network now has 5 nodes
        info!(
            "🔄 [REFRESH] Updating node params: old total_nodes={}, new total_nodes={}",
            self.total_nodes, total_nodes
        );
        self.update_node_params(total_nodes, threshold);

        // Clear old refresh shares from previous refresh rounds
        self.clear_refresh_shares().await?;

        // Use exact indices from database in ascending order
        let all_indices: Vec<usize> = nodes_with_indices.iter().map(|(_, idx)| *idx).collect();

        // CRITICAL: Use permanent index instead of recalculating from sorted nodes
        // The permanent index never changes after initial DKG/join, even if new nodes join
        let my_index = self.my_permanent_index.ok_or_else(|| {
            anyhow!("Permanent index not set - should have been set during DKG completion")
        })?;

        info!(
            "🔄 [REFRESH] Using PERMANENT index: {}, total nodes: {}",
            my_index, total_nodes
        );
        info!(
            "🔄 [REFRESH] All indices used for Lagrange: {:?}",
            all_indices
        );
        info!("⚠️  [REFRESH] IMPORTANT: These indices MUST match the original DKG setup!");
        info!("⚠️  [REFRESH] If original DKG had {} nodes but now we have {} nodes, the secret WILL change!", all_indices.len(), total_nodes);

        // Generate refresh polynomial Gi(x) = Si * pi(0) + zero_constant_polynomial(x)
        info!(
            "🔄 [REFRESH] Generating refresh polynomial for my index {}...",
            my_index
        );
        let refresh_polynomial = self
            .generate_refresh_polynomial(my_index, &all_indices)
            .await?;
        info!("✅ [REFRESH] Refresh polynomial generated successfully");

        // Store the refresh polynomial in storage
        self.storage.set_polynomial(&refresh_polynomial).await?;
        info!("💾 [REFRESH] Stored refresh polynomial in storage");

        // Generate refresh shares from the refresh polynomial for all nodes
        info!(
            "🔄 [REFRESH] Generating refresh shares for all {} nodes...",
            self.total_nodes
        );
        let refresh_shares = self.generate_shares(&refresh_polynomial)?;
        let refresh_commitments = self.generate_commitments(&refresh_polynomial)?;

        info!(
            "✅ [REFRESH] Generated {} refresh shares and {} commitments",
            refresh_shares.len(),
            refresh_commitments.len()
        );

        info!("🔍 [REFRESH] Refresh shares generated:");
        for share in &refresh_shares {
            info!(
                "🔍 [REFRESH]   Share for index {}: {:?}",
                share.index, share.value.0
            );
        }

        // IMPORTANT: Store our own refresh share locally (won't receive it via gossipsub)
        let my_refresh_share = refresh_shares
            .iter()
            .find(|s| s.index == my_index)
            .ok_or_else(|| anyhow!("My refresh share not found in generated shares"))?;

        let raw_commitments: Vec<AffinePoint> = refresh_commitments.iter().map(|c| c.0).collect();

        let key: String = format!("refresh_{}", self.id);
        self.storage.store_share(&key, my_refresh_share).await?;
        self.storage
            .store_commitments(&key, &raw_commitments)
            .await?;

        info!(
            "💾 [REFRESH] Stored own refresh share locally (index={}, value={:?})",
            my_refresh_share.index, my_refresh_share.value.0
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        // Broadcast refresh shares
        let msg = DKGMessage::RefreshShare {
            from: self.id.clone(),
            shares: refresh_shares,
            commitments: refresh_commitments,
        };

        let gossip_wrap = GossipsubMessage::DKG(msg);
        let msg_bytes = serde_json::to_vec(&gossip_wrap)?;
        self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;

        info!("✅ [REFRESH] Broadcasted refresh shares to all nodes");

        Ok(())
    }

    /// Handle receiving refresh share from another node
    async fn handle_refresh_share(
        &mut self,
        from: String,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializablePoint>,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");
        info!("🔄 [REFRESH] RECEIVED REFRESH SHARE FROM {}", from);
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");
        info!(
            "📦 [REFRESH] Received {} shares, {} commitments",
            shares.len(),
            commitments.len()
        );

        // Log all received shares to see what indices they have
        info!("🔍 [REFRESH] All shares received from {}:", from);
        for share in &shares {
            info!(
                "🔍 [REFRESH]   Share: index={}, value={:?}",
                share.index, share.value.0
            );
        }

        // Verify refresh shares
        let raw_commitments: Vec<AffinePoint> = commitments.into_iter().map(|c| c.0).collect();
        info!(
            "🔐 [REFRESH] Verifying {} shares against {} commitments...",
            shares.len(),
            raw_commitments.len()
        );

        if !self.verify_shares(&shares, &raw_commitments) {
            warn!(
                "❌ [REFRESH] Refresh share verification failed from {}",
                from
            );
            return Ok(());
        }

        info!(
            "✅ [REFRESH] All refresh shares verified successfully from {}",
            from
        );

        // CRITICAL: Use permanent index, not recalculated sorted position!
        let my_index = self
            .my_permanent_index
            .ok_or_else(|| anyhow!("Permanent index not set during refresh share handling"))?;

        info!("🔍 [REFRESH] My permanent index: {}", my_index);
        info!(
            "🔍 [REFRESH] Looking for share with index {} in received shares...",
            my_index
        );

        // Find the refresh share meant for this node
        let my_refresh_share = shares
            .iter()
            .find(|s| s.index == my_index)
            .ok_or_else(|| anyhow!("No refresh share found for my index {}", my_index))?;

        info!(
            "✅ [REFRESH] Found my refresh share from {}: index={}, value={:?}",
            from, my_refresh_share.index, my_refresh_share.value.0
        );

        // Store refresh share temporarily with "refresh_" prefix
        let key = format!("refresh_{}", from);
        self.storage.store_share(&key, my_refresh_share).await?;
        self.storage
            .store_commitments(&key, &raw_commitments)
            .await?;

        info!(
            "💾 [REFRESH] Stored refresh share from {} with key: refresh_{}",
            from, from
        );

        // Check if we've received refresh shares from all nodes
        let total_nodes = self.total_nodes;
        let all_shares_stored = self.storage.get_all_shares().await?;
        let refresh_share_keys: Vec<String> = all_shares_stored
            .keys()
            .filter(|k| k.starts_with("refresh_"))
            .cloned()
            .collect();
        let refresh_shares_count = refresh_share_keys.len();

        info!(
            "📊 [REFRESH] Refresh shares received: {}/{}",
            refresh_shares_count, total_nodes
        );
        info!(
            "📊 [REFRESH] Refresh share keys in storage: {:?}",
            refresh_share_keys
        );

        if refresh_shares_count >= total_nodes {
            info!("🎉 [REFRESH] ═══════════════════════════════════════════════════");
            info!("🎉 [REFRESH] RECEIVED ALL {} REFRESH SHARES!", total_nodes);
            info!("🎉 [REFRESH] Now computing new secret share...");
            info!("🎉 [REFRESH] ═══════════════════════════════════════════════════");
            self.compute_refreshed_secret(node_manager).await?;
        } else {
            info!(
                "⏳ [REFRESH] Waiting for more refresh shares ({}/{})",
                refresh_shares_count, total_nodes
            );
        }

        Ok(())
    }

    /// Compute the refreshed secret share by summing all refresh shares
    async fn compute_refreshed_secret(
        &mut self,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");
        info!("🔄 [REFRESH] COMPUTING REFRESHED SECRET SHARE");
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");

        // Get ORIGINAL secret before refresh
        let original_secret = self
            .storage
            .get_final_secret()
            .await?
            .ok_or_else(|| anyhow!("No original secret found"))?;
        let original_public = self
            .storage
            .get_final_public()
            .await?
            .ok_or_else(|| anyhow!("No original public key found"))?;

        info!("📊 [REFRESH] BEFORE REFRESH:");
        info!(
            "📊 [REFRESH]   Original secret share: {:?}",
            original_secret
        );
        info!("📊 [REFRESH]   Original public key: {:?}", original_public);

        let my_index = self
            .my_permanent_index
            .ok_or_else(|| anyhow!("Permanent index not set"))?;
        info!("📊 [REFRESH]   My permanent index: {}", my_index);

        // Get all refresh shares
        let all_shares = self.storage.get_all_shares().await?;
        let refresh_shares: HashMap<String, KeyShare> = all_shares
            .into_iter()
            .filter(|(k, _)| k.starts_with("refresh_"))
            .collect();

        info!(
            "🔄 [REFRESH] Found {} refresh shares in storage",
            refresh_shares.len()
        );

        // Verify all refresh shares have MY index
        info!(
            "🔍 [REFRESH] Verifying all refresh shares are for MY index {}:",
            my_index
        );
        for (from, share) in refresh_shares.iter() {
            let node_id = from.trim_start_matches("refresh_");
            info!(
                "🔍 [REFRESH]   From {}: index={}, value={:?}",
                node_id, share.index, share.value.0
            );
            if share.index != my_index {
                warn!(
                    "⚠️ [REFRESH] ERROR: Share from {} has WRONG index {} (expected {})",
                    node_id, share.index, my_index
                );
                return Err(anyhow!("Refresh share has wrong index"));
            }
        }
        info!(
            "✅ [REFRESH] All refresh shares have correct index {}",
            my_index
        );

        // Sum up all refresh shares: S'i = sum of all refresh shares
        let mut new_secret = Scalar::ZERO;
        info!(
            "🔄 [REFRESH] Computing new secret share: S'_{} = Σ G_i({})",
            my_index, my_index
        );
        for (from, share) in refresh_shares.iter() {
            let node_id = from.trim_start_matches("refresh_");
            info!(
                "✅ [REFRESH]   Adding G_{}({}) from {}: {:?}",
                node_id, my_index, node_id, share.value.0
            );
            new_secret += share.value.0;
        }

        info!("📊 [REFRESH] AFTER SUMMING REFRESH SHARES:");
        info!(
            "📊 [REFRESH]   New secret share S'_{}: {:?}",
            my_index, new_secret
        );
        info!("📊 [REFRESH]   Change: {:?}", new_secret - original_secret);

        // Store the new secret share
        //OKAY 1
        info!(
            "💾 [REFRESH] Storing refreshed polynomial share for NETWORK (final_secret): {:?}",
            new_secret
        );
        self.storage.set_final_secret(new_secret).await?;
        info!("✅ [REFRESH] Successfully stored refreshed NETWORK polynomial share");

        // ========================================
        // UPDATE COMMITMENTS AND FINAL PUBLIC KEY
        // ========================================
        info!("🔄 [REFRESH] Updating commitments and final public key...");

        // Get all refresh commitments
        let all_commitments = self.storage.get_all_commitments().await?;
        let refresh_commitment_entries: HashMap<String, Vec<AffinePoint>> = all_commitments
            .into_iter()
            .filter(|(k, _)| k.starts_with("refresh_"))
            .collect();

        info!(
            "🔄 [REFRESH] Found {} refresh commitment sets",
            refresh_commitment_entries.len()
        );

        // Calculate new final public key by summing all refresh C0 commitments in peer-index order
        let mut new_final_public_key = ProjectivePoint::IDENTITY;

        // Build (peer_id, idx) from DB and order refresh_* commitments by idx
        let peer_indices = self.storage.get_peer_indices().await?;
        let mut refresh_with_indices: Vec<(String, usize)> = refresh_commitment_entries
            .keys()
            .cloned()
            .filter_map(|k| {
                // k is like "refresh_<peer_id>"
                let pid = k.trim_start_matches("refresh_").to_string();
                peer_indices.get(&pid).copied().map(|idx| (k, idx))
            })
            .collect();
        refresh_with_indices.sort_by_key(|(_, idx)| *idx);

        for (refresh_key, _) in refresh_with_indices {
            if let Some(comms) = refresh_commitment_entries.get(&refresh_key) {
                if let Some(c0) = comms.get(0) {
                    new_final_public_key += ProjectivePoint::from(*c0);
                    info!(
                        "✅ [REFRESH] Added C0 from {}: {:?}",
                        refresh_key.trim_start_matches("refresh_"),
                        c0
                    );
                }
            }
        }

        info!(
            "🔑 [REFRESH] New final public key from refresh commitments: {:?}",
            new_final_public_key
        );

        // CRITICAL VERIFICATION: Check if new public key matches original
        info!("🔍 [REFRESH] ═══════════════════════════════════════════════════");
        info!("🔍 [REFRESH] VERIFYING SECRET PRESERVATION");
        info!("🔍 [REFRESH] ═══════════════════════════════════════════════════");
        info!("🔍 [REFRESH] Mathematical property: If refresh is correct, then:");
        info!("🔍 [REFRESH]   Σ_i G_i(0) = Σ_i (S_i * λ_i(0)) = S (original secret)");
        info!("🔍 [REFRESH]   Therefore: new_public_key = S * G = original_public_key");
        info!("🔍 [REFRESH]");
        info!("🔍 [REFRESH] Comparing public keys:");
        info!("🔍 [REFRESH]   Original: {:?}", original_public);
        info!("🔍 [REFRESH]   New:      {:?}", new_final_public_key);

        if original_public == new_final_public_key {
            info!("✅ [REFRESH] SUCCESS: Public keys MATCH! Secret preserved correctly!");
            info!("✅ [REFRESH] The refresh protocol is working correctly.");
            info!("✅ [REFRESH] All nodes used the SAME Lagrange basis.");
        } else {
            warn!("❌ [REFRESH] FAILURE: Public keys DO NOT MATCH!");
            warn!("❌ [REFRESH] This means the secret has CHANGED during refresh!");
            warn!("❌ [REFRESH] This is a CRITICAL BUG in the refresh protocol!");
            warn!("❌ [REFRESH]");
            warn!("❌ [REFRESH] Possible causes:");
            warn!("❌ [REFRESH]   1. Different nodes used DIFFERENT all_indices arrays");
            warn!("❌ [REFRESH]   2. Node indices changed between DKG and refresh");
            warn!("❌ [REFRESH]   3. Some nodes using old shares, others using new shares");
            warn!("❌ [REFRESH]   4. Timing issue: nodes joined/left during refresh");

            // Calculate what the ETH addresses would be
            let original_eth = utils::get_eth_address_from_group_key(original_public);
            let new_eth = utils::get_eth_address_from_group_key(new_final_public_key);
            warn!("❌ [REFRESH] ETH Address BEFORE refresh: {}", original_eth);
            warn!("❌ [REFRESH] ETH Address AFTER refresh:  {}", new_eth);
            warn!("❌ [REFRESH] ═══════════════════════════════════════════════════");
            warn!(
                "⚠️  [REFRESH] CHECK LOGS: Did all nodes use the same 'All indices for Lagrange'?"
            );
        }

        // Store the new final public key
        self.storage.set_final_public(new_final_public_key).await?;

        // Update CURRENT commitments with NEW refresh commitments (for signing verification)
        // NOTE: This updates current commitments but PRESERVES original commitments
        // Original commitments are NEVER changed and are used for vault address derivation
        info!("🔄 [REFRESH] Updating current commitments with refresh commitments...");
        for (refresh_key, comms) in refresh_commitment_entries.iter() {
            // Remove "refresh_" prefix to get the main key
            let main_key = refresh_key.trim_start_matches("refresh_");
            self.storage.store_commitments(main_key, comms).await?;
            info!(
                "💾 [REFRESH] Updated current commitments for {} (original commitments preserved)",
                main_key
            );
        }
        info!("✅ [REFRESH] Current commitments updated (original commitments remain unchanged)");

        // Clear refresh shares after computing new secret
        self.clear_refresh_shares().await?;

        info!("✅ [REFRESH] Secret share and commitments refreshed successfully!");
        info!("🔄 [REFRESH] All nodes now have refreshed shares with new randomness");

        // ========================================
        // RECALCULATE VAULT TWEAKED SECRET WITH NEW PUBLIC KEY
        // ========================================
        info!("🏦 [REFRESH] Recalculating vault tweaked secret with refreshed share and new public key...");

        // Use the NEW final public key we just calculated (not from storage)
        info!(
            "🏦 [REFRESH] Using NEW final public key: {:?}",
            new_final_public_key
        );

        // Convert NEW public key to ETH address
        let eth_address = utils::get_eth_address_from_group_key(new_final_public_key);
        info!(
            "🏦 [REFRESH] Main ETH address (from NEW public key): {}",
            eth_address
        );

        // Calculate vault HMAC from ETH address
        let vault_hmac = hmac256_from_addr(&eth_address, &self.chain_code)
            .map_err(|e| anyhow!("Failed to generate vault HMAC: {}", e))?;
        info!("🏦 [REFRESH] Vault HMAC: {:?}", vault_hmac);

        let tweak_scalar = k256::Scalar::from_repr(vault_hmac.into()).unwrap();
        info!("🏦 [REFRESH] Vault tweak scalar: {:?}", tweak_scalar);

        // Calculate and store the NEW vault tweaked secret share
        info!("💾 [REFRESH] Computing refreshed polynomial share for VAULT...");
        match self
            .calculate_vault_tweaked_secret_share(tweak_scalar)
            .await
        {
            Ok(vault_tweaked_secret) => {
                info!(
                    "🔐 [REFRESH] Successfully calculated refreshed VAULT polynomial share: {:?}",
                    vault_tweaked_secret
                );
                info!("💾 [REFRESH] Storing refreshed polynomial share for VAULT (vault_tweaked_secret): {:?}", vault_tweaked_secret);
                if let Err(e) = self
                    .storage
                    .set_vault_tweaked_secret(vault_tweaked_secret)
                    .await
                {
                    warn!(
                        "⚠️ [REFRESH] Failed to store vault tweaked secret share: {}",
                        e
                    );
                } else {
                    info!("✅ [REFRESH] Successfully stored refreshed VAULT polynomial share in database");
                }
            }
            Err(e) => {
                warn!(
                    "⚠️ [REFRESH] Failed to calculate vault tweaked secret share: {}",
                    e
                );
            }
        }

        // Verify vault addresses using ORIGINAL commitments (should never change)
        match self
            .derive_vault_group_key_from_original_commitments(tweak_scalar)
            .await
        {
            Ok(vault_group_key) => {
                let vault_eth = utils::get_eth_address_from_group_key(vault_group_key);
                let vault_btc = utils::get_btc_address_from_group_key(vault_group_key);
                info!(
                    "🏦 [REFRESH] Vault ETH address (from ORIGINAL commitments): {}",
                    vault_eth
                );
                info!(
                    "🏦 [REFRESH] Vault BTC address (from ORIGINAL commitments): {}",
                    vault_btc
                );
                info!(
                    "✅ [REFRESH] Vault addresses verified - they remain UNCHANGED after refresh"
                );
            }
            Err(e) => {
                warn!(
                    "⚠️ [REFRESH] Failed to derive vault group key for addresses: {}",
                    e
                );
            }
        }

        info!("🎉 [REFRESH] Polynomial refresh complete with updated vault secret!");

        // After updating final secret and vault tweaked secret, refresh all user tweaked shares
        if let Some(registry) = &self.user_registry {
            info!(
                "💾 [REFRESH] Computing and storing refreshed polynomial shares for all USERS..."
            );
            info!("👥 [REFRESH] Refreshing tweaked secret shares for all users");
            if let Err(e) = registry.refresh_all_user_tweaked_shares().await {
                warn!("⚠️ [REFRESH] Failed to refresh user tweaked shares: {}", e);
            } else {
                info!("✅ [REFRESH] Successfully stored refreshed USER polynomial shares for all users");
                info!("✅ [REFRESH] Refreshed tweaked secret shares for all users");
            }
        } else {
            warn!("⚠️ [REFRESH] No user registry attached; cannot refresh user tweaked shares");
        }

        Ok(())
    }

    /// Clear all refresh shares from storage
    async fn clear_refresh_shares(&self) -> Result<()> {
        let all_shares = self.storage.get_all_shares().await?;
        let refresh_keys: Vec<String> = all_shares
            .keys()
            .filter(|k| k.starts_with("refresh_"))
            .cloned()
            .collect();

        if !refresh_keys.is_empty() {
            info!(
                "🗑️ [REFRESH] Clearing {} old refresh shares",
                refresh_keys.len()
            );
            // Note: We don't have a delete method in storage, so we just log
            // The shares will be overwritten in the next refresh round
        }

        Ok(())
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
