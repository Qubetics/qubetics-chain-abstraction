use crate::dkg::{artifacts::DKGMessage, DKGNode};
use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{GossipsubMessage, KeyShare, SerializablePoint};
use crate::utils::hmac_helper::hmac_scalar_mod_n;
use crate::{utils, NodeMembership};
use anyhow::{anyhow, Result};
use ff::{Field, PrimeField};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use serde_json;
use std::collections::HashMap;
use tokio::time::Duration;
use tracing::{info, warn};

impl DKGNode {
    fn generate_zero_constant_polynomial(&self) -> Result<Vec<Scalar>> {
        let mut rng = rand::rngs::OsRng;
        let threshold = self.threshold();
        let mut coefficients = Vec::with_capacity(threshold);

        // First coefficient (constant term) is ZERO
        coefficients.push(Scalar::ZERO);

        // Remaining coefficients are random
        for _ in 1..threshold {
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
            "🔐 [REFRESH] My current secret share S_{} loaded (value redacted)",
            my_index
        );

        // Calculate Lagrange coefficient pi(0)
        info!(
            "🔢 [REFRESH] Calculating Lagrange coefficient λ_{}(0) over provided indices",
            my_index
        );
        let lagrange_coeff = self.calculate_lagrange_coefficient(my_index, all_indices);
        info!("🔢 [REFRESH] λ_{}(0) computed (value redacted)", my_index);

        // Calculate the constant term that THIS node contributes to the secret
        let constant_contribution = my_secret_share * lagrange_coeff;
        info!(
            "🎯 [REFRESH] Computed node contribution S_{} * λ_{}(0) (value redacted)",
            my_index, my_index
        );
        info!("📝 [REFRESH] Mathematical invariant: Σ_i (S_i * λ_i(0)) = S (original secret)");
        info!(
            "📝 [REFRESH] If all nodes use indices {:?}, sum should equal original secret",
            all_indices
        );

        // Generate zero-constant polynomial (constant term = 0, other coefficients random)
        let zero_poly = self.generate_zero_constant_polynomial()?;
        info!("🎲 [REFRESH] Generated zero-constant polynomial for randomization");

        // Gi(x) = Si * λi(0) + zero_constant_polynomial(x)
        let mut refresh_poly = zero_poly.clone();

        // The constant term: Gi(0) = Si * λi(0) + 0 = Si * λi(0)
        refresh_poly[0] = constant_contribution;

        info!(
            "🔄 [REFRESH] Refresh polynomial G_{}(x) constructed",
            my_index
        );
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");

        Ok(refresh_poly)
    }

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
            self.total_nodes(),
            total_nodes
        );
        self.update_node_params(total_nodes, threshold)?;

        // Clear old refresh shares from previous refresh rounds
        self.clear_refresh_shares().await?;

        // Use exact indices from database in ascending order
        let all_indices: Vec<usize> = nodes_with_indices.iter().map(|(_, idx)| *idx).collect();

        // CRITICAL: Use permanent index instead of recalculating from sorted nodes
        // The permanent index never changes after initial DKG/join, even if new nodes join
        let my_index = self.permanent_index().ok_or_else(|| {
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

        // Generate refresh shares from the refresh polynomial for SPECIFIC active node indices
        info!(
            "🔄 [REFRESH] Generating refresh shares for active node indices: {:?}",
            all_indices
        );
        let refresh_shares = self.generate_shares_for_indices(&refresh_polynomial, &all_indices)?;
        let refresh_commitments = self.generate_commitments(&refresh_polynomial)?;

        info!(
            "✅ [REFRESH] Generated {} refresh shares and {} commitments",
            refresh_shares.len(),
            refresh_commitments.len()
        );

        info!("🔍 [REFRESH] Refresh shares generated for all indices");

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
            "💾 [REFRESH] Stored own refresh share locally (index={})",
            my_refresh_share.index
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

    pub(super) async fn handle_refresh_share(
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
        info!(
            "🔍 [REFRESH] All shares received from {} (values redacted)",
            from
        );

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
            .permanent_index()
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
            "✅ [REFRESH] Found my refresh share from {}: index={}",
            from, my_refresh_share.index
        );

        // Store refresh share temporarily with "refresh_" prefix
        let key = format!("refresh_{from}");
        self.storage.store_share(&key, my_refresh_share).await?;
        self.storage
            .store_commitments(&key, &raw_commitments)
            .await?;

        info!(
            "💾 [REFRESH] Stored refresh share from {} with key: refresh_{}",
            from, from
        );

        // Check if we've received refresh shares from all ACTIVE nodes
        let expected_active_nodes = shares.len();
        let local_node_manager_count = node_manager.get_active_nodes().len();

        let all_shares_stored = self.storage.get_all_shares().await?;
        let refresh_share_keys: Vec<String> = all_shares_stored
            .keys()
            .filter(|k| k.starts_with("refresh_"))
            .cloned()
            .collect();
        let refresh_shares_count = refresh_share_keys.len();

        info!(
            "📊 [REFRESH] Refresh shares received: {}/{}",
            refresh_shares_count, expected_active_nodes
        );
        info!(
            "📊 [REFRESH] Expected nodes (from message): {}, Local node_manager: {}",
            expected_active_nodes, local_node_manager_count
        );
        info!(
            "📊 [REFRESH] Refresh share keys in storage: {:?}",
            refresh_share_keys
        );

        if local_node_manager_count != expected_active_nodes {
            warn!("⚠️ [REFRESH] MISMATCH: Local node_manager has {} nodes but received message for {} nodes", 
                  local_node_manager_count, expected_active_nodes);
            warn!("⚠️ [REFRESH] This node might not have detected disconnect yet. Using message count as truth.");
        }

        if refresh_shares_count >= expected_active_nodes {
            info!("🎉 [REFRESH] ═══════════════════════════════════════════════════");
            info!(
                "🎉 [REFRESH] RECEIVED ALL {} REFRESH SHARES!",
                expected_active_nodes
            );
            info!("🎉 [REFRESH] Now computing new secret share...");
            info!("🎉 [REFRESH] ═══════════════════════════════════════════════════");
            self.compute_refreshed_secret().await?;
        } else {
            info!(
                "⏳ [REFRESH] Waiting for more refresh shares ({}/{})",
                refresh_shares_count, expected_active_nodes
            );
        }

        Ok(())
    }

    async fn compute_refreshed_secret(&mut self) -> Result<()> {
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");
        info!("🔄 [REFRESH] COMPUTING REFRESHED SECRET SHARE");
        info!("🔄 [REFRESH] ═══════════════════════════════════════════════════");

        // Get ORIGINAL secret before refresh
        let _original_secret = self
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
        info!("📊 [REFRESH]   Original secret share loaded (value redacted)");
        info!("📊 [REFRESH]   Original public key: {:?}", original_public);

        let my_index = self
            .permanent_index()
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
            info!("🔍 [REFRESH]   From {}: index={}", node_id, share.index);
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
                "✅ [REFRESH]   Adding G_{}({}) from {}",
                node_id, my_index, node_id
            );
            new_secret += share.value.0;
        }

        info!("📊 [REFRESH] AFTER SUMMING REFRESH SHARES:");
        info!(
            "📊 [REFRESH]   New secret share S'_{} computed (value redacted)",
            my_index
        );
        info!("📊 [REFRESH]   Secret delta computed (value redacted)");

        info!("💾 [REFRESH] Storing refreshed polynomial share for NETWORK");
        self.storage.set_final_secret(new_secret).await?;
        info!("✅ [REFRESH] Successfully stored refreshed NETWORK polynomial share");

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
                if let Some(c0) = comms.first() {
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

        info!("🏦 [REFRESH] Recalculating vault tweaked secret with refreshed share...");

        info!(
            "🏦 [REFRESH] Using NEW final public key for vault address: {:?}",
            new_final_public_key
        );

        let eth_address = utils::get_eth_address_from_group_key(new_final_public_key);
        info!(
            "🏦 [REFRESH] Main ETH address from NEW public key: {}",
            eth_address
        );

        // Use hmac_scalar_mod_n to safely reduce HMAC modulo curve order
        let vault_hmac_reduced = hmac_scalar_mod_n(&eth_address, &self.chain_code)
            .map_err(|e| anyhow!("Failed to generate vault HMAC: {}", e))?;
        info!("🏦 [REFRESH] Vault HMAC derived and reduced mod curve order (value redacted)");

        // from_repr will always succeed since vault_hmac_reduced is already reduced mod curve order
        let tweak_scalar = Option::from(k256::Scalar::from_repr(vault_hmac_reduced.into()))
            .ok_or_else(|| anyhow!("Failed to create scalar from reduced vault HMAC"))?;
        info!("🏦 [REFRESH] Vault tweak scalar derived from HMAC (value redacted)");

        info!("💾 [REFRESH] Computing refreshed polynomial share for VAULT...");
        match self
            .calculate_vault_tweaked_secret_share(tweak_scalar)
            .await
        {
            Ok(vault_tweaked_secret) => {
                info!("🔐 [REFRESH] Successfully calculated refreshed VAULT polynomial share");
                info!("💾 [REFRESH] Storing refreshed polynomial share for VAULT (value redacted)");
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
                    info!("✅ [REFRESH] Successfully stored refurbished VAULT polynomial share in database");
                }
            }
            Err(e) => {
                warn!(
                    "⚠️ [REFRESH] Failed to calculate vault tweaked secret share: {}",
                    e
                );
            }
        }

        let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
        let vault_group_key = new_final_public_key + tweak_point;

        let vault_eth = utils::get_eth_address_from_group_key(vault_group_key);
        let vault_btc = utils::get_btc_address_from_group_key(vault_group_key);
        info!(
            "🏦 [REFRESH] Derived vault group key: {:?}",
            vault_group_key
        );
        info!("🏦 [REFRESH] Vault ETH address: {}", vault_eth);
        info!("🏦 [REFRESH] Vault BTC address: {}", vault_btc);

        if let Err(e) = self
            .storage
            .set_vault_addresses(&vault_eth, &vault_btc)
            .await
        {
            warn!("⚠️ [REFRESH] Failed to store vault addresses: {}", e);
        } else {
            info!("✅ [REFRESH] Successfully stored vault addresses in database");
        }

        if let Err(e) = self.storage.set_vault_group_key(vault_group_key).await {
            warn!("⚠️ [REFRESH] Failed to store vault group key: {}", e);
        } else {
            info!("✅ [REFRESH] Successfully stored vault group key in database");
        }

        info!("🎉 [REFRESH] Polynomial refresh complete with updated vault secret!");

        if let Some(registry) = &self.user_intent_manager {
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

    async fn clear_refresh_shares(&self) -> Result<()> {
        let all_shares = self.storage.get_all_shares().await?;
        let refresh_keys: Vec<String> = all_shares
            .keys()
            .filter(|k| k.starts_with("refresh_"))
            .cloned()
            .collect();

        if !refresh_keys.is_empty() {
            info!(
                "🗑️ [REFRESH] Deleting {} old refresh shares from storage",
                refresh_keys.len()
            );

            for key in &refresh_keys {
                if let Err(e) = self.storage.delete_share(key).await {
                    warn!("⚠️ [REFRESH] Failed to delete refresh share {}: {}", key, e);
                } else {
                    info!("✅ [REFRESH] Deleted refresh share: {}", key);
                }

                if let Err(e) = self.storage.delete_commitment(key).await {
                    warn!(
                        "⚠️ [REFRESH] Failed to delete refresh commitments {}: {}",
                        key, e
                    );
                } else {
                    info!("✅ [REFRESH] Deleted refresh commitments: {}", key);
                }
            }

            info!("✅ [REFRESH] Successfully cleared all old refresh shares and commitments");
        } else {
            info!("ℹ️ [REFRESH] No old refresh shares to clear");
        }

        Ok(())
    }
}
