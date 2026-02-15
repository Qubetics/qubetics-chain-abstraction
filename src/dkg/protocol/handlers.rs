use crate::dkg::{
    artifacts::{DKGMessage, DKGStatus},
    DKGNode,
};
use crate::types::{KeyShare, SerializablePoint, SerializableScalar};
use crate::utils;
use crate::utils::hmac_helper::hmac_scalar_mod_n;
use crate::NodeMembership;
use anyhow::{anyhow, Result};
use ff::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use tracing::{info, warn};

impl DKGNode {
    pub async fn handle_message(
        &mut self,
        msg: DKGMessage,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
        match msg {
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
            DKGMessage::NodeDisconnected { .. } => {
                info!("📢 [DISCONNECT] Notification handled at network layer");
            }
            DKGMessage::CommitmentBroadcast {
                from,
                commitments,
                round,
            } => {
                info!(
                    "🔐 [DKG-SECURE] Received commitment broadcast from {} (round {})",
                    from, round
                );
                self.handle_commitment_broadcast(from, commitments).await?;
            }
        }
        Ok(())
    }

    /// Handle commitment broadcast (public, safe to broadcast)
    /// Individual shares are received via P2P RPC (SendDKGShare)
    async fn handle_commitment_broadcast(
        &mut self,
        from: String,
        commitments: Vec<SerializablePoint>,
    ) -> Result<()> {
        info!(
            "🔐 [DKG-SECURE] Processing {} commitments from {}",
            commitments.len(),
            from
        );

        // Store commitments for verification when we receive the share via RPC
        let raw_commitments: Vec<k256::AffinePoint> = commitments.iter().map(|c| c.0).collect();
        self.storage
            .store_commitments(&from, &raw_commitments)
            .await?;

        info!(
            "✅ [DKG-SECURE] Stored {} commitments from {} (waiting for unicast share)",
            raw_commitments.len(),
            from
        );

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

    pub async fn handle_share_validation(
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

    pub(crate) async fn check_completion(
        &mut self,
        node_manager: Box<dyn NodeMembership>,
    ) -> Result<()> {
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
            "Validations :{:?}",
            self.storage.get_all_validations().await?
        );

        info!(
            "🔍 [DKG] Checking DKG completion - shares: {}, validations: {}, valid validations: {}",
            shares_len, validations_len, valid_validations
        );

        if valid_validations >= (node_manager.get_total_nodes()) * (node_manager.get_total_nodes())
            && shares_len >= node_manager.get_total_nodes()
        {
            info!(
                "✅ [DKG] Required validations: {} and valid validations: {}",
                (node_manager.get_total_nodes()) * (node_manager.get_total_nodes()),
                valid_validations
            );

            let received = self.storage.get_received_shares().await.unwrap_or_default();
            let expected = self.storage.get_expected_shares().await.unwrap_or_default();

            let received_set: std::collections::HashSet<_> = received.iter().collect();
            let expected_set: std::collections::HashSet<_> = expected.iter().collect();

            if !expected.is_empty() && received_set != expected_set {
                let pending = self.storage.get_pending_shares().await.unwrap_or_default();
                warn!(
                    "⚠️ [DKG] Received shares ({:?}) do not match expected shares ({:?}). Pending: {:?}",
                    received, expected, pending
                );
                return Err(anyhow!(
                    "DKG failed: received shares do not match expected shares"
                ));
            }

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

        // Store the initial DKG signer count (used by HRW to exclude observer nodes)
        let signer_count = commitments.len();
        if let Err(e) = self.storage.set_dkg_signer_count(signer_count) {
            warn!("⚠️ [DKG] Failed to store DKG signer count: {}", e);
        } else {
            info!("🔢 [DKG] Stored initial DKG signer count: {}", signer_count);
        }

        info!("🎯 [DKG] DKG COMPLETED for node {}!", self.id);
        info!(
            "🔐 [DKG] Final secret share computed and stored for node {}",
            self.id
        );
        info!("🔑 [DKG] Final public key: {:?}", final_public_key);

        // Compute and store all share public keys for all peers
        if let Err(e) = self.compute_and_store_all_share_pubkeys().await {
            warn!("⚠️ [DKG] Failed to compute and store share pubkeys: {}", e);
        } else {
            info!("✅ [DKG] Successfully computed and stored all share pubkeys");

            // Log all stored share pubkeys for verification
            if let Err(e) = self.storage.log_all_stored_share_pubkeys().await {
                warn!("⚠️ [DKG] Failed to log stored share pubkeys: {}", e);
            }
        }

        if let Some(callback) = self.completion_callback.take() {
            callback(final_secret_share, final_public_key);
        }

        let eth_address = utils::get_eth_address_from_group_key(final_public_key);
        let btc_address = utils::get_btc_address_from_group_key(final_public_key);

        info!("📬 Ethereum Address from Group Key: {}", eth_address);
        info!("📬 Bitcoin Address from Group Key: {}", btc_address);

        // Use hmac_scalar_mod_n to safely reduce HMAC modulo curve order
        let vault_hmac_reduced = hmac_scalar_mod_n(&eth_address, &self.chain_code)
            .map_err(|e| anyhow!("Failed to generate vault HMAC: {}", e))?;

        info!("🏦 [DKG] === VAULT GENERATION STARTED ===");
        info!("🏦 [DKG] Main ETH address: {}", eth_address);
        info!("🏦 [DKG] Vault HMAC derived and reduced mod curve order (value redacted)");

        // from_repr will always succeed since vault_hmac_reduced is already reduced mod curve order
        let tweak_scalar = Option::from(Scalar::from_repr(vault_hmac_reduced.into()))
            .ok_or_else(|| anyhow!("Failed to create scalar from reduced vault HMAC"))?;
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
                    .set_liquidity_operator_addresses(&vault_eth, &vault_btc)
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

        // Mark initial DKG as complete (works for 3+ nodes)
        if self.total_nodes() >= 3 {
            if let Err(e) = self.storage.set_initial_dkg_complete(true).await {
                warn!("⚠️ [DKG] Failed to set initial DKG complete flag: {}", e);
            } else {
                info!(
                    "✅ [DKG] Marked initial DKG as complete for {} nodes",
                    self.total_nodes()
                );
            }
        }

        Ok(())
    }
}
