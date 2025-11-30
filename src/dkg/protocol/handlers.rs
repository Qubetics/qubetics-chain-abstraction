use crate::dkg::{
    artifacts::{DKGMessage, DKGStatus},
    DKGNode,
};
use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{GossipsubMessage, KeyShare, SerializablePoint, SerializableScalar};
use crate::utils::hmac_helper::hmac256_from_addr;
use crate::{utils, NodeMembership};
use anyhow::{anyhow, Result};
use ff::PrimeField;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde_json;
use tracing::{info, warn};

impl DKGNode {
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
                round: _,
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
                new_node_index,
            } => {
                info!(
                    "📨 Received new node share from {} to {} (new_node_index: {})",
                    from, to, new_node_index
                );
                if to == self.id {
                    self.handle_new_node_share_received(
                        from,
                        share,
                        commitment,
                        new_node_index,
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
            DKGMessage::NodeDisconnected { .. } => {
                info!("📢 [DISCONNECT] Notification handled at network layer");
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

    pub(super) async fn handle_share_distribution(
        &mut self,
        from: String,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializablePoint>,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        let raw_commitments: Vec<AffinePoint> = commitments.into_iter().map(|c| c.0).collect();

        let node_index = self.get_node_index(node_manager.clone())?;

        info!("🔍 [DKG] === SHARE DISTRIBUTION RECEIVED ===");
        info!(
            "📥 [DKG] Node {} received {} shares from node {}",
            self.id,
            shares.len(),
            from
        );

        info!("🔍 [DKG] All shares received from {}:", from);
        for (i, share) in shares.iter().enumerate() {
            info!("🔍 [DKG] Share {}: index={}", i + 1, share.index);
        }

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
                    "✅ [DKG] Found valid share for node {} from {}",
                    self.id, from
                );

                self.storage.store_share(&from, &share).await?;
                self.storage
                    .store_commitments(&from, &raw_commitments)
                    .await?;

                self.handle_share_validation(self.id.clone(), from.clone(), true, node_manager)
                    .await?;

                let round = self.current_round();
                let validation_msg = DKGMessage::ShareValidation {
                    from: self.id.clone(),
                    to: from,
                    is_valid: true,
                    round,
                };
                let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
                let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
                self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
            } else {
                info!(
                    "❌ [DKG] Share for index {} not found in shares from {}",
                    node_index, from
                );
                let round = self.current_round();
                let validation_msg = DKGMessage::ShareValidation {
                    from: self.id.clone(),
                    to: from,
                    is_valid: false,
                    round,
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
            let round = self.current_round();
            let validation_msg = DKGMessage::ShareValidation {
                from: self.id.clone(),
                to: from,
                is_valid: false,
                round,
            };
            let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
            let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
            self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
        }
        Ok(())
    }

    fn get_node_index(&self, _node_manager: Box<dyn NodeMembership>) -> Result<usize> {
        info!("🔍 [DKG] === NODE INDEX LOOKUP (DB-only) ===");
        info!("🔍 [DKG] Current node ID: {}", self.id);

        match self.storage.get_peer_index_for(&self.id) {
            Ok(Some(idx)) => {
                info!(
                    "🔢 [DKG] Using stored peer index {} for node {}",
                    idx, self.id
                );
                Ok(idx)
            }
            Ok(None) => Err(anyhow!(
                "No stored peer index found for {}; cannot determine node index",
                self.id
            )),
            Err(e) => Err(anyhow!(
                "Failed to read peer index from DB for {}: {:?}",
                self.id,
                e
            )),
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

        is_valid
    }

    pub fn verify_shares(&self, shares: &[KeyShare], commitments: &[AffinePoint]) -> bool {
        if shares.is_empty() || commitments.is_empty() {
            return false;
        }

        info!("🔍 [DKG] === MULTIPLE SHARES VERIFICATION ===");
        info!("🔍 [DKG] Verifying {} shares", shares.len());

        for share in shares {
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
                return false;
            } else {
                info!("✅ Share verification passed for index {}", share.index);
            }
        }

        info!("✅ All shares verified successfully");
        true
    }

    async fn handle_share_validation(
        &mut self,
        from: String,
        to: String,
        is_valid: bool,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        self.storage.add_validation(&to, &from, is_valid).await?;
        info!("📊 Validation from {} to {}: {}", from, to, is_valid);
        self.check_completion(node_manager).await?;
        Ok(())
    }

    async fn check_completion(&mut self, node_manager: Box<dyn NodeMembership>) -> Result<()> {
        let (shares_len, validations_len, valid_validations) = {
            let validations = self.storage.get_all_validations().await?;
            let shares = self.storage.get_all_shares().await?;

            info!("📊 [DKG] Total shares stored: {}", shares.len());
            for (sender, share) in shares.iter() {
                info!(
                    "📊 [DKG] Share from {}: index={}, value={:?}",
                    sender, share.index, share.value.0
                );
            }

            info!("🎉 [DKG] Validations: {:?}", validations);
            let valid_validations: usize = validations
                .values()
                .map(|v| v.values().filter(|&&valid| valid).count())
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
        let node_index = self.get_node_index(node_manager)?;
        info!(
            "🔍 [DKG] Node {} calculating final secret share using shares for index {}",
            self.id, node_index
        );

        let mut final_secret_share = Scalar::ZERO;
        info!("🔐 [DKG] Calculating final secret share...");

        for (from, share) in shares.iter() {
            if share.index == node_index {
                info!(
                    "✅ [DKG] Using share from {} with index {}",
                    from, share.index
                );
                final_secret_share += share.value.0;
            } else {
                info!(
                    "❌ [DKG] Skipping share from {} with index {}",
                    from, share.index
                );
            }
        }

        let mut final_public_key = ProjectivePoint::IDENTITY;

        let peer_indices = self.storage.get_peer_indices().await?;
        let mut solver_with_indices: Vec<(String, usize)> = commitments
            .keys()
            .cloned()
            .filter_map(|sid| peer_indices.get(&sid).copied().map(|idx| (sid, idx)))
            .collect();
        solver_with_indices.sort_by_key(|(_, idx)| *idx);

        for (sid, _) in solver_with_indices {
            if let Some(comms) = commitments.get(&sid) {
                if let Some(c0) = comms.first() {
                    final_public_key += ProjectivePoint::from(*c0);
                } else {
                    warn!("⚠️ [DKG] Solver {} has no C0 (index 0 missing)", sid);
                }
            }
        }

        self.storage.set_final_secret(final_secret_share).await?;
        self.storage.set_final_public(final_public_key).await?;
        self.storage.set_my_permanent_index(node_index).await?;
        self.set_permanent_index(node_index);
        info!("🔢 [DKG] Stored permanent index: {}", node_index);

        for (from, comms) in commitments.iter() {
            if let Err(e) = self.storage.store_original_commitments(from, comms).await {
                warn!(
                    "⚠️ [DKG] Failed to store original commitments for {}: {}",
                    from, e
                );
            }
        }

        self.transition_status(DKGStatus::Completed)?;

        info!("🎯 [DKG] DKG COMPLETED for node {}!", self.id);
        info!(
            "🔐 [DKG] Final secret share computed and stored for node {}",
            self.id
        );
        info!("🔑 [DKG] Final public key: {:?}", final_public_key);

        if let Some(callback) = self.completion_callback.take() {
            callback(final_secret_share, final_public_key);
        }

        let eth_address = utils::get_eth_address_from_group_key(final_public_key);
        let btc_address = utils::get_btc_address_from_group_key(final_public_key);

        info!("📬 Ethereum Address from Group Key: {}", eth_address);
        info!("📬 Bitcoin Address from Group Key: {}", btc_address);

        let vault_hmac = hmac256_from_addr(&eth_address, &self.chain_code)
            .map_err(|e| anyhow!("Failed to generate vault HMAC: {}", e))?;

        info!("🏦 [DKG] === VAULT GENERATION STARTED ===");
        info!("🏦 [DKG] Main ETH address: {}", eth_address);
        info!("🏦 [DKG] Vault HMAC derived (value redacted)");

        let tweak_scalar = Scalar::from_bytes_reduced(&FieldBytes::from(vault_hmac));
        info!("🏦 [DKG] Vault tweak scalar derived from HMAC (value redacted)");

        match self
            .calculate_vault_tweaked_secret_share(tweak_scalar)
            .await
        {
            Ok(vault_tweaked_secret) => {
                info!("🔐 [DKG] Successfully calculated vault tweaked secret share");
                if let Err(e) = self
                    .storage
                    .set_vault_tweaked_secret(vault_tweaked_secret)
                    .await
                {
                    warn!("⚠️ [DKG] Failed to store vault tweaked secret share: {}", e);
                }
            }
            Err(e) => {
                warn!(
                    "⚠️ [DKG] Failed to calculate vault tweaked secret share: {}",
                    e
                );
            }
        }

        match self
            .derive_vault_group_key_from_original_commitments(tweak_scalar)
            .await
        {
            Ok(vault_group_key) => {
                let vault_eth = utils::get_eth_address_from_group_key(vault_group_key);
                let vault_btc = utils::get_btc_address_from_group_key(vault_group_key);
                info!("🏦 [DKG] Vault ETH address: {}", vault_eth);
                info!("🏦 [DKG] Vault BTC address: {}", vault_btc);

                if let Err(e) = self
                    .storage
                    .set_vault_addresses(&vault_eth, &vault_btc)
                    .await
                {
                    warn!("⚠️ [DKG] Failed to store vault addresses: {}", e);
                }

                if let Err(e) = self.storage.set_vault_group_key(vault_group_key).await {
                    warn!("⚠️ [DKG] Failed to store vault group key: {}", e);
                }
            }
            Err(e) => {
                warn!("⚠️ [DKG] Failed to derive vault group key: {}", e);
            }
        }

        if self.total_nodes() == 4 {
            if let Err(e) = self.storage.set_initial_dkg_complete(true).await {
                warn!("⚠️ [DKG] Failed to set initial DKG complete flag: {}", e);
            }
        }

        Ok(())
    }
}
