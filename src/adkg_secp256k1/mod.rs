use crate::{utils, NodeMembership};
use crate::utils::hmac_helper::hmac256_from_addr;
use anyhow::{Result, anyhow};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use k256::elliptic_curve::group::Group;
use ethers::core::k256::ecdsa::Error;
use ff::{Field, PrimeField};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{any, usize};
use tokio::sync::mpsc;
use tracing::info;
use tracing::warn;

use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{
    ChannelMessage, GossipsubMessage, KeyShare, SerializablePoint, SerializableScalar,
};
use crate::database::DkgStorage;

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
        round : u64,
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
        }
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
        let final_secret_share = self.storage.get_final_secret().await?
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

        let mut solver_ids: Vec<String> = commitments.keys().cloned().collect();
        solver_ids.sort();

        // P_base = Σ C0_i
        let mut p_base = ProjectivePoint::IDENTITY;
        let mut added = 0usize;
        for sid in &solver_ids {
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
            return Err(anyhow!("No C0 found in any solver commitments; cannot derive base group key"));
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

    
    pub async fn start_dkg(&mut self,node_manager: Box<dyn NodeMembership>) -> Result<()> {
        info!(
            "🚀 Starting DKG for node {} with threshold {} and total nodes {}",
            self.id, self.threshold, self.total_nodes
        );

        let polynomial = self.generate_polynomial()?;
        info!("🔢 Generated polynomial: {:?}", polynomial);
        let shares = self.generate_shares(&polynomial)?;
        let commitments = self.generate_commitments(&polynomial)?;

        self.status = DKGStatus::Started;
        info!("📤 Broadcasting DKG shares and commitments...");
        tokio::time::sleep(Duration::from_secs(1)).await;
        {
            let my_shares = shares.clone();
            let my_commitments = commitments.clone();
            // This will verify, store in database
            // and even send you a local “validation” message if you want.
            self.handle_share_distribution(self.id.clone(), my_shares, my_commitments,node_manager)
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
        info!("📊 [DKG] Node {} generating shares for {} nodes", self.id, self.total_nodes);
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
                info!("🔍 [DKG]   Term {}: coeff[{}] * x^{} = {:?} * {:?}^{} = {:?}", 
                      j, j, j, coeff, x, j, term);
            }

            info!("🔍 [DKG] Final share for index {}: y = {:?}", i, y);

            shares.push(KeyShare {
                index: i,
                value: SerializableScalar(y),
            });
        }
        
        info!("🔍 [DKG] === GENERATED SHARES SUMMARY ===");
        for (i, share) in shares.iter().enumerate() {
            info!("🔍 [DKG] Share {}: index={}, value={:?}", i+1, share.index, share.value.0);
        }
        info!("🔍 [DKG] === END GENERATED SHARES SUMMARY ===");
        
        info!("✅ [DKG] Node {} generated {} shares", self.id, shares.len());
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

    pub async fn handle_message(&mut self, msg: DKGMessage,node_manager: Box<dyn NodeMembership>,
) -> Result<()> {
        match msg {
            DKGMessage::ShareDistribution {
                from,
                shares,
                commitments,
            } => {
                info!("📥 Received share distribution from {}", from);
                self.handle_share_distribution(from, shares, commitments,node_manager.clone())
                    .await?;
            }
            DKGMessage::ShareValidation { from, to, is_valid ,round} => {
                info!(
                    "✅ Received share validation from {} for {}: {}",
                    from, to, is_valid
                );
                self.handle_share_validation(from, to, is_valid,node_manager).await?;
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
        info!("📥 [DKG] Node {} received {} shares from node {}", self.id, shares.len(), from);
        
        info!("🔍 [DKG] All shares received from node {}:", from);
        for (i, share) in shares.iter().enumerate() {
            info!(
                "🔍 [DKG] Share {}: index={}, value={:?} (intended for node with index {})",
                i + 1, share.index, share.value.0, share.index
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
                info!("🔍 [DKG] Storing share from node {}: index={}, value={:?}", 
                      from, share.index, share.value.0);
                
                self.storage.store_share(&from, &share).await?;
                self.storage
                    .store_commitments(&from, &raw_commitments)
                    .await?;

                // Log current state of all stored shares
                let current_shares = self.storage.get_all_shares().await?;
                info!("🔍 [DKG] Current total shares stored: {}", current_shares.len());
                info!("🔍 [DKG] All stored shares:");
                for (sender, stored_share) in current_shares.iter() {
                    info!(
                        "🔍 [DKG] Stored share from {}: index={}, value={:?}",
                        sender, stored_share.index, stored_share.value.0
                    );
                }
                info!("🔍 [DKG] === END STORING SHARE ===");

                self.handle_share_validation(self.id.clone(), from.clone(), true,node_manager)
                    .await?;

                let validation_msg = DKGMessage::ShareValidation {
                    from: self.id.clone(),
                    to: from,
                    is_valid: true,
                    round : self.round,
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
                    round : self.round,
                };
                let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
                let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
                self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
            }
        } else {
            info!("❌ [DKG] Share verification failed for shares from {}", from);
            let validation_msg = DKGMessage::ShareValidation {
                from: self.id.clone(),
                to: from,
                is_valid: false,
                round : self.round,
            };
            let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
            let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
            self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
        }
        Ok(())
    }

    fn get_node_index(&self,node_manager: Box<dyn NodeMembership>) -> usize {
        // First try to parse as a number
        let mut ids: Vec<String> = node_manager
            .get_active_nodes()
            .into_iter()
            .map(|p| p.to_string())
            .collect();

        info!("🔍 [DKG] === NODE INDEX CALCULATION ===");
        info!("🔍 [DKG] Current node ID: {}", self.id);
        info!("🔍 [DKG] All active nodes (before sorting): {:?}", ids);

        ids.sort();

        info!("🔍 [DKG] All active nodes (after sorting): {:?}", ids);
        
        let index = ids.iter()
           .position(|id| id == &self.id)
           .map(|i| i + 1)
           .unwrap_or_else(|| {
               tracing::error!("DKGNode id {} not in NodeManager list", self.id);
               1
           });
        
        info!("🔍 [DKG] Node {} assigned index: {}", self.id, index);
        info!("🔍 [DKG] === END NODE INDEX CALCULATION ===");
        
        index
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
        info!("🔍 [DKG] Using x = Scalar::from({}) for verification", share_index);

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
        
        info!("🔍 [DKG] Share verification result: {}", if is_valid { "✅ PASS" } else { "❌ FAIL" });
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
            info!("🔍 [DKG] Using x = Scalar::from({}) for verification", share.index);
            
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

    async fn check_completion(&mut self,node_manager: Box<dyn NodeMembership>) -> Result<()> {
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
                "✅ [DKG] Required validations: {} and valid validations: {}",(node_manager.get_total_nodes()) * (node_manager.get_total_nodes()),valid_validations
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

    async fn generate_group_key(&mut self,node_manager: Box<dyn NodeMembership>) -> Result<()> {
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
        info!("🔍 [DKG] Node {} has {} total shares stored", self.id, shares.len());
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
        info!("🔍 [DKG] Starting with final_secret_share = {:?}", final_secret_share);

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

        info!("📊 [DKG] Final calculation summary: used {} shares, skipped {} shares", used_shares, skipped_shares);

        let first_comms: Vec<AffinePoint> = commitments
            .values()
            .filter_map(|comms| comms.get(0).cloned())
            .collect();

        // Calculate final public key (sum of all commitment constant terms)
        let mut final_public_key = ProjectivePoint::IDENTITY;
        let mut keys: Vec<_> = commitments.keys().collect();
        keys.sort();
        // for comms in commitments.values() {
        //     if !comms.is_empty() {
        //         final_public_key += ProjectivePoint::from(comms[0]);
        //     }
        // }
        for key in keys {
            if let Some(comms) = commitments.get(key) {
                if !comms.is_empty() {
                    final_public_key += ProjectivePoint::from(comms[0]);
                }
            }
        }

        // Store the results
        self.storage.set_final_secret(final_secret_share).await?;
        self.storage.set_final_public(final_public_key).await?;

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
            let was_used = if share.index == node_index { "✅ USED" } else { "❌ SKIPPED" };
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
        match self.calculate_vault_tweaked_secret_share(tweak_scalar).await {
            Ok(vault_tweaked_secret) => {
                info!("🔐 [DKG] Successfully calculated vault tweaked secret share: {:?}", vault_tweaked_secret);
                if let Err(e) = self.storage.set_vault_tweaked_secret(vault_tweaked_secret).await {
                    warn!("⚠️ [DKG] Failed to store vault tweaked secret share: {}", e);
                } else {
                    info!("✅ [DKG] Successfully stored vault tweaked secret share in database");
                }
            }
            Err(e) => {
                warn!("⚠️ [DKG] Failed to calculate vault tweaked secret share: {}", e);
            }
        }

        // Derive and store the vault group key and addresses
        match self
            .derive_user_specific_group_key_from_commitments(tweak_scalar)
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
                info!("📊 [DKG] Node {} has {} shares stored", self.id, shares.len());
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
