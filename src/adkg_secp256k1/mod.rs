use crate::{utils, NodeMembership};
use anyhow::Result;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use k256::elliptic_curve::group::Group;
use ethers::core::k256::ecdsa::Error;
use ff::Field;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{any, usize};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::info;
use tracing::warn;

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
    shares: RwLock<HashMap<String, KeyShare>>,
    commitments: RwLock<HashMap<String, Vec<AffinePoint>>>,
    // Store updated commitments per user AND per solver: ethereum_address -> (solver_id -> updated_commitments)
    updated_commitments_per_user: RwLock<HashMap<String, HashMap<String, Vec<AffinePoint>>>>,
    validations: RwLock<HashMap<String, Vec<bool>>>,
    message_tx: mpsc::Sender<ChannelMessage>,
    final_secret_share: RwLock<Option<Scalar>>,
    final_public_key: RwLock<Option<ProjectivePoint>>,
    completion_callback: Option<DKGCompletionCallback>,
    round: u64,
}

impl DKGNode {
    pub fn new(
        id: String,
        threshold: usize,
        total_nodes: usize,
        message_tx: mpsc::Sender<ChannelMessage>,
    ) -> Self {
        Self {
            id,
            status: DKGStatus::New,
            threshold,
            total_nodes,
            shares: RwLock::new(HashMap::new()),
            commitments: RwLock::new(HashMap::new()),
            updated_commitments_per_user: RwLock::new(HashMap::new()),
            validations: RwLock::new(HashMap::new()),
            message_tx,
            final_secret_share: RwLock::new(None),
            final_public_key: RwLock::new(None),
            completion_callback: None,
            round: 0,
        }
    }

    pub async fn reset(&mut self) {
        // 1) clear all the in-flight maps
        self.shares.write().await.clear();
        self.commitments.write().await.clear();
        self.updated_commitments_per_user.write().await.clear();
        self.validations.write().await.clear();

        // 2) wipe out any previously computed key material
        *self.final_secret_share.write().await = None;
        *self.final_public_key.write().await   = None;

        // 3) go back to the "New" status
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

    /// Update commitments array using HMAC tweak while preserving mathematical relationship
    /// This implements the mathematical relationship:
    /// C0' = C0 + t*G (constant term updated)
    /// C1' = C1 (slope unchanged)
    /// C2' = C2 (higher terms unchanged)
    /// Verification: s_i'*G = (s_i + t)*G = s_i*G + t*G = C0' + i*C1 + i^2*C2 + ...
    pub async fn update_commitments_with_tweak(&self, ethereum_address: &str, hmac_tweak: &Scalar) -> Result<()> {
        info!("🔐 [DKG] Updating commitments array with HMAC tweak for user: {}", ethereum_address);
        
        // Get the original commitments from all solvers
        let commitments = self.commitments.read().await;
        if commitments.is_empty() {
            warn!("❌ [DKG] No commitments available for update");
            return Err(anyhow::anyhow!("No commitments available"));
        }
        
        // Process commitments from each solver and store per solver
        for (solver_id, solver_commitments) in commitments.iter() {
            info!("🔐 [DKG] Processing commitments from solver: {} for user: {}", solver_id, ethereum_address);
            
            if solver_commitments.is_empty() {
                continue;
            }
            
            // Create updated commitments array for this specific solver
            let mut updated_commitments = Vec::new();
            
            // Update constant term commitment: C0' = C0 + t*G
            let c0 = solver_commitments[0];
            let c0_prime = AffinePoint::from(ProjectivePoint::from(c0) + ProjectivePoint::GENERATOR * *hmac_tweak);
            updated_commitments.push(c0_prime);
            
            info!("🔐 [DKG] Solver {}: C0' = C0 + t*G = {:?} + {:?}*G = {:?}", 
                  solver_id, c0, hmac_tweak, c0_prime);
            
            // Higher order commitments unchanged: C1' = C1, C2' = C2, ...
            for (i, commitment) in solver_commitments.iter().skip(1).enumerate() {
                updated_commitments.push(*commitment);
                info!("🔐 [DKG] Solver {}: C{}' = C{} = {:?}", solver_id, i+1, i+1, commitment);
            }
            
            // Store the updated commitments for this specific solver and user
            {
                let mut updated_comms = self.updated_commitments_per_user.write().await;
                updated_comms
                    .entry(ethereum_address.to_string())
                    .or_insert_with(HashMap::new)
                    .insert(solver_id.clone(), updated_commitments);
            }
            
            info!("🔐 [DKG] Stored updated commitments for solver: {} and user: {}", solver_id, ethereum_address);
        }
        
        info!("🔐 [DKG] Successfully updated commitments arrays for user: {} across all solvers", ethereum_address);
        info!("🔐 [DKG] Mathematical relationship preserved: C0' = C0 + t*G, C1' = C1, C2' = C2, ...");
        
        Ok(())
    }

    /// Get the updated commitments array for a specific user and solver
    pub async fn get_updated_commitments_for_user_and_solver(&self, ethereum_address: &str, solver_id: &str) -> Option<Vec<AffinePoint>> {
        let updated_comms = self.updated_commitments_per_user.read().await;
        updated_comms
            .get(ethereum_address)
            .and_then(|solver_comms| solver_comms.get(solver_id).cloned())
    }

    /// Get all updated commitments for a specific user (across all solvers)
    pub async fn get_all_updated_commitments_for_user(&self, ethereum_address: &str) -> Option<HashMap<String, Vec<AffinePoint>>> {
        let updated_comms = self.updated_commitments_per_user.read().await;
        updated_comms.get(ethereum_address).cloned()
    }

    /// Get all users with updated commitments
    pub async fn get_users_with_updated_commitments(&self) -> Vec<String> {
        let updated_comms = self.updated_commitments_per_user.read().await;
        updated_comms.keys().cloned().collect()
    }

    /// Get all solvers with updated commitments for a specific user
    pub async fn get_solvers_with_updated_commitments_for_user(&self, ethereum_address: &str) -> Vec<String> {
        let updated_comms = self.updated_commitments_per_user.read().await;
        updated_comms
            .get(ethereum_address)
            .map(|solver_comms| solver_comms.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Get a summary of all updated commitments for debugging
    pub async fn get_updated_commitments_summary(&self) -> String {
        let updated_comms = self.updated_commitments_per_user.read().await;
        
        if updated_comms.is_empty() {
            return "No updated commitments available".to_string();
        }
        
        let mut summary = String::new();
        summary.push_str(&format!("Updated Commitments Summary ({} users):\n", updated_comms.len()));
        
        let mut user_keys: Vec<_> = updated_comms.keys().collect();
        user_keys.sort();
        
        for ethereum_address in user_keys {
            if let Some(user_solver_commitments) = updated_comms.get(ethereum_address) {
                summary.push_str(&format!("  User {}: {} solvers\n", ethereum_address, user_solver_commitments.len()));
                
                let mut solver_keys: Vec<_> = user_solver_commitments.keys().collect();
                solver_keys.sort();
                
                for solver_id in solver_keys {
                    if let Some(solver_commitments) = user_solver_commitments.get(solver_id) {
                        summary.push_str(&format!("    Solver {}: {} commitments\n", solver_id, solver_commitments.len()));
                        
                        if !solver_commitments.is_empty() {
                            let c0_prime = solver_commitments[0];
                            summary.push_str(&format!("      C0': {:?}\n", c0_prime));
                        }
                    }
                }
            }
        }
        
        summary
    }

    /// Derive NEW group key from updated commitments for a specific user
    /// This calculates a user-specific group key from commitments that have been updated with HMAC tweaks
    /// The result is DIFFERENT from the original DKG group key
    pub async fn derive_user_specific_group_key_from_updated_commitments(&self, ethereum_address: &str) -> Result<ProjectivePoint> {
        info!("🔐 [DKG] Deriving NEW user-specific group key from updated commitments for user: {}", ethereum_address);
        
        let updated_comms = self.updated_commitments_per_user.read().await;
        
        if let Some(user_solver_commitments) = updated_comms.get(ethereum_address) {
            if user_solver_commitments.is_empty() {
                return Err(anyhow::anyhow!("No updated commitments available for user: {}", ethereum_address));
            }
            
            info!("🔐 [DKG] Found {} solvers with updated commitments for user: {}", 
                  user_solver_commitments.len(), ethereum_address);
            
            let mut new_group_key = ProjectivePoint::IDENTITY;
            let mut solver_keys: Vec<_> = user_solver_commitments.keys().collect();
            solver_keys.sort(); // Ensure deterministic ordering
            
            for solver_id in solver_keys {
                if let Some(solver_commitments) = user_solver_commitments.get(solver_id) {
                    if !solver_commitments.is_empty() {
                        // Get the updated C0' commitment (constant term after HMAC tweak)
                        let c0_prime = solver_commitments[0];
                        info!("🔐 [DKG] Solver {}: C0' = {:?} (updated with HMAC tweak)", solver_id, c0_prime);
                        
                        // Add to new group key: P_new = Σ(C0'ᵢ) where C0'ᵢ = C0ᵢ + tᵢ*G
                        new_group_key += ProjectivePoint::from(c0_prime);
                        info!("🔐 [DKG] Added solver {} C0' to new group key, current sum: {:?}", solver_id, new_group_key);
                    } else {
                        warn!("⚠️ [DKG] Solver {} has empty commitments array", solver_id);
                    }
                }
            }
            
            info!("🔑 [DKG] NEW user-specific group key derived from updated commitments: {:?}", new_group_key);
            
            // Compare with original group key to show the difference
            {
                let guard = self.final_public_key.read().await;
                if let Some(original_group_key) = guard.as_ref() {
                    let difference = new_group_key - *original_group_key;
                    info!("🔄 [DKG] Difference from original group key: {:?}", difference);
                    info!("🔐 [DKG] Original: {:?} → New: {:?}", original_group_key, new_group_key);
                }
            }
            
            Ok(new_group_key)
            
        } else {
            Err(anyhow::anyhow!("No updated commitments found for user: {}", ethereum_address))
        }
    }

    /// Generate blockchain addresses from the NEW user-specific group key
    /// This uses the group key derived from updated commitments, not the original DKG group key
    pub async fn derive_user_addresses_from_updated_commitments(&self, ethereum_address: &str) -> Result<(String, String)> {
        info!("🔐 [DKG] Deriving addresses from NEW user-specific group key for user: {}", ethereum_address);
        
        // Derive the NEW group key from updated commitments
        let new_group_key = self.derive_user_specific_group_key_from_updated_commitments(ethereum_address).await?;
        
        // Generate addresses from this NEW group key
        let eth_address = utils::get_eth_address_from_group_key(new_group_key);
        let btc_address = utils::get_btc_address_from_group_key(new_group_key);
        
        info!("📬 [DKG] Derived addresses from NEW group key for user {}:", ethereum_address);
        info!("   New Group Key: {:?}", new_group_key);
        info!("   Ethereum: {}", eth_address);
        info!("   Bitcoin: {}", btc_address);
        
        Ok((eth_address, btc_address))
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
            // This will verify, store in `self.shares`/`self.commitments`
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
                
                self.shares.write().await.insert(from.clone(), share);
                self.commitments
                    .write()
                    .await
                    .insert(from.clone(), raw_commitments);

                // Log current state of all stored shares
                let current_shares = self.shares.read().await;
                info!("🔍 [DKG] Current total shares stored: {}", current_shares.len());
                info!("🔍 [DKG] All stored shares:");
                for (sender, stored_share) in current_shares.iter() {
                    info!(
                        "🔍 [DKG] Stored share from {}: index={}, value={:?}",
                        sender, stored_share.index, stored_share.value.0
                    );
                }
                drop(current_shares); // Release the read lock
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
        {
            let mut validations = self.validations.write().await;
            validations
                .entry(to.clone())
                .or_insert_with(Vec::new)
                .push(is_valid);

            info!("📊 Validation from {} to {}: {}", from, to, is_valid);
        } // validations lock guard dropped here
        self.check_completion(node_manager).await?;
        Ok(())
    }

    async fn check_completion(&mut self,node_manager: Box<dyn NodeMembership>) -> Result<()> {
        let (shares_len, validations_len, valid_validations) = {
            let validations = self.validations.read().await;
            let shares = self.shares.read().await;
            
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
        }; // lock guards dropped here

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
        let shares = self.shares.read().await;
        let commitments = self.commitments.read().await;
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

        // 2. Print out the array of first commitments
        println!("First commitments array: {:#?}", first_comms);
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
        *self.final_secret_share.write().await = Some(final_secret_share);
        *self.final_public_key.write().await = Some(final_public_key);

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

        Ok(())
    }

    pub async fn get_final_secret_share(&self) -> Option<Scalar> {
        self.final_secret_share.read().await.clone()
    }

    pub async fn get_final_public_key(&self) -> Option<ProjectivePoint> {
        self.final_public_key.read().await.clone()
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
        let shares = self.shares.read().await;
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

    /// Verify that tweaked shares satisfy the mathematical relationship
    /// s_i'*G = (s_i + t)*G = s_i*G + t*G = C0' + i*C1 + i^2*C2 + ...
    pub async fn verify_tweaked_shares(&self, ethereum_address: &str, solver_id: &str, tweaked_shares: &[KeyShare], hmac_tweak: &Scalar) -> bool {
        info!("🔐 [DKG] Verifying tweaked shares for user: {} from solver: {} with mathematical relationship", ethereum_address, solver_id);
        
        let updated_commitments = self.get_updated_commitments_for_user_and_solver(ethereum_address, solver_id).await;
        if updated_commitments.is_none() {
            warn!("❌ [DKG] No updated commitments available for user: {} from solver: {}", ethereum_address, solver_id);
            return false;
        }
        
        let commitments = updated_commitments.unwrap();
        info!("🔐 [DKG] Using {} updated commitments from solver: {} for verification", commitments.len(), solver_id);
        
        for share in tweaked_shares {
            let i = Scalar::from(share.index as u64);
            let mut expected_point = ProjectivePoint::IDENTITY;
            
            // Compute C0' + i*C1 + i^2*C2 + ... + i^(t-1)*C(t-1)
            for (j, commitment) in commitments.iter().enumerate() {
                let mut i_pow = Scalar::ONE;
                for _ in 0..j {
                    i_pow *= i;
                }
                let term = ProjectivePoint::from(*commitment) * i_pow;
                expected_point += term;
                
                info!("🔐 [DKG] Share {}: Term {}: C{}' * i^{} = {:?} * {:?}^{} = {:?}", 
                      share.index, j, j, j, commitment, i, j, term);
            }
            
            // Compute actual tweaked share point: s_i'*G
            let actual_point = ProjectivePoint::GENERATOR * share.value.0;
            
            // Verify: s_i'*G = C0' + i*C1 + i^2*C2 + ...
            if actual_point != expected_point {
                warn!("❌ [DKG] Verification failed for share {}: expected != actual", share.index);
                warn!("❌ [DKG] Expected: {:?}", expected_point);
                warn!("❌ [DKG] Actual: {:?}", actual_point);
                return false;
            }
            
            info!("✅ [DKG] Share {} verification passed: s_{}'*G = C0' + {}*C1 + {}*C2 + ...", 
                  share.index, share.index, share.index, share.index);
        }
        
        info!("✅ [DKG] All tweaked shares verified successfully for user: {} from solver: {}", ethereum_address, solver_id);
        true
    }
}
