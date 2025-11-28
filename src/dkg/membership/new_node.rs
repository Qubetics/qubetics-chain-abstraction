use crate::dkg::{
    artifacts::{DKGMessage, DKGStatus},
    DKGNode,
};
use anyhow::{anyhow, Result};
use ff::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use tracing::{info, warn};

use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{GossipsubMessage, KeyShare, SerializablePoint, SerializableScalar};
use crate::utils::hmac_helper::hmac256_from_addr;
use crate::{utils, NodeMembership};
use serde_json;

impl DKGNode {
    /// Called by existing nodes when a new node joins
    /// Uses the existing polynomial to send a share to the new node
    /// The polynomial is NOT modified - we just evaluate it at the new node's index
    pub async fn handle_new_node_joined(
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
            "🔍 [NEW_NODE] Share computed for new node at index {}",
            new_node_index
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
            new_node_index, // Pass the calculated index to the new node
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
    pub async fn handle_new_node_share_received(
        &mut self,
        from: String,
        share: KeyShare,
        commitments: Vec<SerializablePoint>,
        new_node_index: usize,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        info!("📨 [NEW_NODE] Received share from existing node {}", from);
        info!("📨 [NEW_NODE] Share index: {}", share.index);

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
        let total_nodes = self.total_nodes();
        info!(
            "📊 [NEW_NODE] Total shares received: {}/{}",
            shares.len(),
            total_nodes - 1
        );

        // If we have shares from all existing nodes (total_nodes - 1), calculate the final secret share
        if shares.len() >= total_nodes - 1 {
            info!("🎉 [NEW_NODE] Received all shares from existing nodes! Calculating final secret share...");

            // Calculate final secret share by summing all received shares
            let mut final_secret_share = Scalar::ZERO;

            info!("🔍 [NEW_NODE] === FINAL SECRET SHARE CALCULATION ===");
            info!("🔍 [NEW_NODE] Starting final secret share accumulation");

            for (from_node, share) in shares.iter() {
                info!("✅ [NEW_NODE] Adding share from {}", from_node);
                final_secret_share += share.value.0;
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
                    .map(|(sid, idx)| format!("{sid}:{idx}"))
                    .collect::<Vec<_>>()
            );

            for (sid, _) in solver_with_indices {
                if let Some(comms) = commitments_map.get(&sid) {
                    if let Some(c0) = comms.first() {
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

            // Store the permanent index that was assigned by existing nodes
            self.storage.set_my_permanent_index(new_node_index).await?;
            self.set_permanent_index(new_node_index);
            info!(
                "🔢 [NEW_NODE] Stored permanent index: {} (assigned by existing nodes)",
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
            self.transition_status(DKGStatus::Completed)?;

            // Log the final results
            info!("🎯 [NEW_NODE] DKG COMPLETED for new node {}!", self.id);
            info!(
                "🔐 [NEW_NODE] Final secret share computed and stored for new node {}",
                self.id
            );
            info!("🔑 [NEW_NODE] Final public key: {:?}", final_public_key);
            info!("📊 [NEW_NODE] Total shares collected: {}", shares.len());
            info!("✅ [NEW_NODE] DKG status: {:?}", self.get_status());

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
            info!("🏦 [NEW_NODE] Vault HMAC derived (value redacted)");

            let tweak_scalar = Scalar::from_repr(vault_hmac.into()).unwrap();
            info!("🏦 [NEW_NODE] Vault tweak scalar derived from HMAC (value redacted)");

            // Calculate and store the vault tweaked secret share
            match self
                .calculate_vault_tweaked_secret_share(tweak_scalar)
                .await
            {
                Ok(vault_tweaked_secret) => {
                    info!("🔐 [NEW_NODE] Successfully calculated vault tweaked secret share");
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
}
