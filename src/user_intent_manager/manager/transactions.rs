use super::*;
use tracing::{error, info, warn};

impl UserIntentManager {
    /// Store transaction ID for user_aggregated_address -> network_aggregated_address
    pub async fn store_user_to_vault_tx_id(
        &self,
        intent_hash: &str,
        tx_id: &str,
        solver_id: Option<&str>,
    ) -> Result<(), String> {
        info!("🔗 [DB_USER_REGISTRY] Processing user_to_network transaction ID storage:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  📤 Transaction ID: {}", tx_id);
        info!("  🔄 Transaction type: user_aggregated_address -> network_aggregated_address");

        match self
            .intent_storage
            .store_user_to_network_tx_id(intent_hash, tx_id, solver_id.map(|s| s.to_string()))
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Successfully stored user_to_network_tx_id");
                info!("  🎯 Intent: {}", intent_hash);
                info!("  📤 TX ID: {}", tx_id);
                Ok(())
            }
            Err(e) => {
                error!("❌ [DB_USER_REGISTRY] Failed to store user_to_network_tx_id");
                error!("  🔗 Intent hash: {}", intent_hash);
                error!("  📤 Transaction ID: {}", tx_id);
                error!("  💥 Error: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Store transaction ID for network_aggregated_address -> user_target_address
    pub async fn store_network_to_target_tx_id(
        &self,
        intent_hash: &str,
        tx_id: &str,
        solver_id: Option<&str>,
    ) -> Result<(), String> {
        info!("🔗 [DB_USER_REGISTRY] Processing network_to_target transaction ID storage:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  📥 Transaction ID: {}", tx_id);
        info!("  🔄 Transaction type: network_aggregated_address -> user_target_address");

        // Store the transaction ID first
        match self
            .intent_storage
            .store_network_to_target_tx_id(intent_hash, tx_id, solver_id.map(|s| s.to_string()))
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Successfully stored network_to_target_tx_id");
                info!("  🎯 Intent: {}", intent_hash);
                info!("  📥 TX ID: {}", tx_id);
            }
            Err(e) => {
                error!("❌ [DB_USER_REGISTRY] Failed to store network_to_target_tx_id");
                error!("  🔗 Intent hash: {}", intent_hash);
                error!("  📥 Transaction ID: {}", tx_id);
                error!("  💥 Error: {}", e);
                return Err(e.to_string());
            }
        }

        // Check if this is a TICS transaction and mark intent as Solved
        // Get the intent to check target_chain
        if let Ok(Some(intent)) = self.intent_storage.get_intent(intent_hash).await {
            let target_chain_lower = intent.target_chain.to_lowercase();
            let is_tics = target_chain_lower == "qubetics" || target_chain_lower == "tics";

            if is_tics {
                info!(
                    "💎 [DB_USER_REGISTRY] TICS transaction detected (target_chain: {}), marking intent as Solved",
                    intent.target_chain
                );

                // Find the user who owns this intent
                if let Ok(Some(user)) = self.user_storage.get_user_by_intent_hash(intent_hash).await
                {
                    // Update intent status to Solved
                    if let Err(e) = self
                        .user_storage
                        .update_intent_status(&user.tics_address, intent_hash, IntentStatus::Solved)
                        .await
                    {
                        error!(
                            "⚠️ [DB_USER_REGISTRY] Failed to update intent status to Solved for TICS transaction: {}",
                            e
                        );
                        // Don't fail the whole operation, just log the error
                    } else {
                        info!(
                            "✅ [DB_USER_REGISTRY] Marked intent {} as Solved for user {} (TICS transaction)",
                            intent_hash,
                            user.tics_address
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [DB_USER_REGISTRY] Could not find user for intent {} to update status to Solved",
                        intent_hash
                    );
                }
            } else {
                info!(
                    "₿ [DB_USER_REGISTRY] BTC transaction detected (target_chain: {}), NOT marking intent as Solved",
                    intent.target_chain
                );
            }
        } else {
            warn!(
                "⚠️ [DB_USER_REGISTRY] Could not retrieve intent {} to check target_chain",
                intent_hash
            );
        }

        Ok(())
    }

    /// Store or update the final solver for an intent
    pub async fn store_final_solver(&self, intent_hash: &str, solver: &str) -> Result<(), String> {
        match self
            .intent_storage
            .store_final_solver(intent_hash, solver)
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Successfully stored final solver",);
                info!("  🎯 Intent: {}", intent_hash);
                info!("  🧠 Solver: {}", solver);
                Ok(())
            }
            Err(e) => {
                error!("❌ [DB_USER_REGISTRY] Failed to store final solver");
                error!("  🔗 Intent hash: {}", intent_hash);
                error!("  🧠 Solver: {}", solver);
                error!("  💥 Error: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Store transaction IDs for an intent
    pub async fn store_intent_transaction_ids(
        &self,
        intent_hash: &str,
        user_to_network_tx_id: Option<String>,
        network_to_target_tx_id: Option<String>,
        final_solver_id: Option<String>,
    ) -> Result<(), String> {
        self.intent_storage
            .store_intent_transaction_ids(
                intent_hash,
                user_to_network_tx_id,
                network_to_target_tx_id,
                final_solver_id,
            )
            .await
            .map_err(|e| e.to_string())?;

        info!(
            "✅ [DB_USER_REGISTRY] Updated transaction IDs for intent: {}",
            intent_hash
        );
        Ok(())
    }

    /// Store transaction error message
    pub async fn store_transaction_error(
        &self,
        intent_hash: &str,
        error_message: &str,
        solver_id: Option<&str>,
    ) -> Result<(), String> {
        info!("💥 [DB_USER_REGISTRY] Processing transaction error storage:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  ❌ Error message: {}", error_message);

        match self
            .intent_storage
            .store_transaction_error(intent_hash, error_message, solver_id.map(|s| s.to_string()))
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Successfully stored transaction error");
                info!("  🎯 Intent: {}", intent_hash);
                info!("  ❌ Error: {}", error_message);
                Ok(())
            }
            Err(e) => {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to store transaction error: {}",
                    e
                );
                Err(format!("Database error: {e}"))
            }
        }
    }

    /// Get transaction IDs for an intent hash
    pub async fn get_intent_transaction_ids(
        &self,
        intent_hash: &str,
    ) -> Option<IntentTransactionIds> {
        match self
            .intent_storage
            .get_intent_transaction_ids(intent_hash)
            .await
        {
            Ok(tx_ids) => tx_ids,
            Err(e) => {
                tracing::error!(
                    "Failed to get transaction IDs for intent {}: {}",
                    intent_hash,
                    e
                );
                None
            }
        }
    }

    /// Get all intents with their transaction IDs
    pub async fn get_all_intents_with_transaction_ids(
        &self,
    ) -> HashMap<String, (DepositIntent, Option<IntentTransactionIds>)> {
        match self
            .intent_storage
            .get_all_intents_with_transaction_ids()
            .await
        {
            Ok(intents) => intents,
            Err(e) => {
                tracing::error!("Failed to get intents with transaction IDs: {}", e);
                HashMap::new()
            }
        }
    }

    /// Get intents that have completed both transactions
    pub async fn get_completed_intents(
        &self,
    ) -> Vec<(String, DepositIntent, IntentTransactionIds)> {
        match self.intent_storage.get_completed_intents().await {
            Ok(intents) => intents,
            Err(e) => {
                tracing::error!("Failed to get completed intents: {}", e);
                Vec::new()
            }
        }
    }

    /// Get intents that are missing transaction IDs
    pub async fn get_pending_transaction_intents(
        &self,
    ) -> Vec<(String, DepositIntent, Option<IntentTransactionIds>)> {
        match self.intent_storage.get_pending_transaction_intents().await {
            Ok(intents) => intents,
            Err(e) => {
                tracing::error!("Failed to get pending transaction intents: {}", e);
                Vec::new()
            }
        }
    }

    /// Get intents that have not yet completed UserToVault (no user_to_network_tx_id),
    /// filtered by source chain. Used by the final node to pick a batch for TICS/BTC UserToVault signing.
    /// Returns (intent_hash, intent, user_tics_address) for each intent; only intents with a
    /// registered user are included.
    /// - `batched_only`: None or Some(false) → only intents with status Pending are included.
    /// - `batched_only`: Some(true) → only intents with status Batched and no user_to_network_tx_id are included.
    /// - `excluded_intent_hashes`: when provided, intents whose hash is in this set are skipped (e.g. intents from last N batches).
    pub async fn get_pending_user_to_vault_intents_by_source_chain(
        &self,
        source_chain: &str,
        limit: usize,
        batched_only: Option<bool>,
        excluded_intent_hashes: Option<&std::collections::HashSet<String>>,
    ) -> Vec<(String, DepositIntent, String)> {
        let pending = self.get_pending_transaction_intents().await;
        let source_lower = source_chain.to_lowercase();
        let mut out = Vec::with_capacity(limit.min(pending.len()));
        // Track source addresses already included in this batch to ensure at most
        // one intent per user per batch. Multiple intents from the same source_address
        // cannot be safely processed in a single UserToVault batch because the on-chain
        // nonce/balance would change after the first transfer.
        let mut seen_source_addresses: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (intent_hash, intent, tx_ids) in pending {
            if out.len() >= limit {
                break;
            }
            if excluded_intent_hashes.map_or(false, |ex| ex.contains(&intent_hash)) {
                continue;
            }
            let no_user_tx = tx_ids
                .as_ref()
                .map(|ids| ids.user_to_network_tx_id.is_none())
                .unwrap_or(true);
            if !no_user_tx {
                continue;
            }
            let chain_ok = intent.source_chain.eq_ignore_ascii_case("tics")
                || intent.source_chain.eq_ignore_ascii_case("qubetics");
            if !chain_ok && source_lower != intent.source_chain.to_lowercase() {
                continue;
            }
            if source_lower == "tics" || source_lower == "qubetics" {
                if !intent.source_chain.eq_ignore_ascii_case("tics")
                    && !intent.source_chain.eq_ignore_ascii_case("qubetics")
                {
                    continue;
                }
            } else if intent.source_chain.to_lowercase() != source_lower {
                continue;
            }
            // For BTC-source intents, skip if amount is below Bitcoin dust limit (546 sats).
            // These can never produce a valid on-chain transaction, so mark them Rejected
            // immediately so they are never re-picked in future batch cycles.
            let is_btc_source = intent.source_chain.eq_ignore_ascii_case("bitcoin")
                || intent.source_chain.eq_ignore_ascii_case("btc");
            if is_btc_source {
                let parsed_amount: u64 = intent.amount.parse().unwrap_or(0);
                if parsed_amount < crate::utils::transaction::DUST_LIMIT_SATS {
                    warn!(
                        "⚠️ [BATCH_PICK] Rejecting intent {} — BTC amount {} sats below dust limit {}",
                        intent_hash, parsed_amount, crate::utils::transaction::DUST_LIMIT_SATS
                    );
                    if let Some(user) = self.get_user_by_intent_hash(&intent_hash).await {
                        let _ = self
                            .update_intent_status(
                                &user.tics_address,
                                &intent_hash,
                                IntentStatus::Rejected,
                            )
                            .await;
                    }
                    continue;
                }
            }
            // Skip if we already have an intent from this source address in the batch.
            // The second intent will be picked up in a subsequent batch cycle.
            let source_addr_lower = intent.source_address.to_lowercase();
            if seen_source_addresses.contains(&source_addr_lower) {
                continue;
            }
            if let Some(user) = self.get_user_by_intent_hash(&intent_hash).await {
                let status = user.intent_hashes.get(&intent_hash);
                match batched_only {
                    Some(true) => {
                        // Only Batched intents that don't have user_to_vault tx-id yet
                        if !matches!(status, Some(IntentStatus::Batched)) {
                            continue;
                        }
                    }
                    _ => {
                        // Only Pending intents; exclude Batched and others
                        if matches!(
                            status,
                            Some(IntentStatus::Batched)
                                | Some(IntentStatus::Processing)
                                | Some(IntentStatus::Solved)
                                | Some(IntentStatus::Rejected)
                        ) {
                            continue;
                        }
                    }
                }
                seen_source_addresses.insert(source_addr_lower);
                out.push((intent_hash, intent, user.tics_address));
            }
        }
        out
    }

    /// Check if an intent has both transaction IDs
    pub async fn is_intent_transaction_complete(&self, intent_hash: &str) -> bool {
        match self.get_intent_transaction_ids(intent_hash).await {
            Some(tx_ids) => {
                tx_ids.user_to_network_tx_id.is_some() && tx_ids.network_to_target_tx_id.is_some()
            }
            None => false,
        }
    }

    /// Get transaction completion status for an intent
    pub async fn get_intent_transaction_status(&self, intent_hash: &str) -> (bool, bool) {
        match self.get_intent_transaction_ids(intent_hash).await {
            Some(tx_ids) => (
                tx_ids.user_to_network_tx_id.is_some(),
                tx_ids.network_to_target_tx_id.is_some(),
            ),
            None => (false, false),
        }
    }

    pub async fn store_transaction_status(
        &self,
        tx_hash: &str,
        status: TransactionStatus,
    ) -> Result<(), String> {
        self.tx_status_storage
            .store_status(tx_hash, status.clone())
            .await
            .map_err(|e| e.to_string())?;
        info!("✅ Stored transaction status for {}: {:?}", tx_hash, status);
        Ok(())
    }

    /// Update the status of a transaction hash
    pub async fn update_transaction_status(
        &self,
        tx_hash: &str,
        status: TransactionStatus,
    ) -> Result<(), String> {
        self.tx_status_storage
            .update_status(tx_hash, status.clone())
            .await
            .map_err(|e| e.to_string())?;
        info!(
            "✅ Updated transaction status for {}: {:?}",
            tx_hash, status
        );
        Ok(())
    }

    /// Get the status of a transaction hash
    pub async fn get_transaction_status(&self, tx_hash: &str) -> Option<TransactionStatus> {
        match self.tx_status_storage.get_status(tx_hash).await {
            Ok(status) => status,
            Err(e) => {
                tracing::error!("Failed to get transaction status {}: {}", tx_hash, e);
                None
            }
        }
    }

    /// Get intents that have completed UserToVault transaction but are awaiting NetworkToTarget transaction
    /// Returns: Vec<(intent_hash, DepositIntent, IntentTransactionIds)>
    ///
    /// This is useful for identifying:
    /// - Deposits where users have sent funds to the vault
    /// - But the network hasn't fulfilled the withdrawal to target chain yet
    ///
    /// # Arguments
    /// * `minimum_wait_seconds` - Optional minimum time in seconds since last update.
    ///   If provided, only returns intents that haven't been updated in at least this many seconds.
    ///
    /// # Examples
    /// ```
    /// // Get all awaiting intents
    /// let all = user_intent_manager.get_intents_awaiting_network_fulfillment(None).await;
    ///
    /// // Get only intents not updated in the last 10 seconds
    /// let stale = user_intent_manager.get_intents_awaiting_network_fulfillment(Some(10)).await;
    /// ```
    /// Returns intents that have user_to_network_tx_id but no network_to_target_tx_id yet,
    /// and whose status is NOT Solved (so already-solved intents are excluded from batching).
    pub async fn get_intents_awaiting_network_fulfillment(
        &self,
        minimum_wait_seconds: Option<i64>,
    ) -> Vec<(String, DepositIntent, IntentTransactionIds)> {
        let intents = match self
            .intent_storage
            .get_intents_awaiting_network_fulfillment(minimum_wait_seconds)
            .await
        {
            Ok(list) => list,
            Err(e) => {
                tracing::error!("Failed to get intents awaiting network fulfillment: {}", e);
                return Vec::new();
            }
        };
        let original_len = intents.len();
        // Exclude intents already marked Solved (TICS-TICS and others get marked Solved after fulfillment)
        let mut filtered = Vec::new();
        for (intent_hash, intent, tx_ids) in intents {
            if let Ok(Some(user)) = self
                .user_storage
                .get_user_by_intent_hash(&intent_hash)
                .await
            {
                if let Some(status) = user.intent_hashes.get(&intent_hash) {
                    if *status == IntentStatus::Solved {
                        continue; // Skip solved intents so they are not included in the batch again
                    }
                }
            }
            filtered.push((intent_hash, intent, tx_ids));
        }
        if filtered.len() < original_len {
            info!(
                "📋 [INTENT_MANAGER] Excluded {} already-solved intents from awaiting list ({} remaining)",
                original_len - filtered.len(),

                filtered.len()
            );
        }
        filtered
    }

    /// Reject intents that have been stuck in Pending or Batched status for longer than
    /// `max_age_secs` seconds (default: 3 hours = 10800s). These intents are unlikely to
    /// succeed and should be freed so they stop being picked for batches.
    /// Only user-to-vault intents (those without a `user_to_network_tx_id`) are considered.
    /// Returns the number of intents rejected.
    pub async fn reject_stale_intents(&self, max_age_secs: u64) -> usize {
        let now_secs = chrono::Utc::now().timestamp() as u128;
        let users = match self.user_storage.get_all_users().await {
            Ok(u) => u,
            Err(e) => {
                error!(
                    "❌ [STALE_INTENT] Failed to load users for stale intent sweep: {}",
                    e
                );
                return 0;
            }
        };

        let mut rejected_count = 0usize;

        for (tics_address, user) in &users {
            for (intent_hash, status) in &user.intent_hashes {
                // Only target intents still in Pending or Batched
                if !matches!(status, IntentStatus::Pending | IntentStatus::Batched) {
                    continue;
                }

                // Look up the deposit intent to read its creation timestamp
                let intent = match self.get_intent(intent_hash).await {
                    Some(i) => i,
                    None => continue,
                };

                // Skip intents that already have a user_to_network tx ID (Phase 1 complete)
                if let Some(tx_ids) = self.get_intent_transaction_ids(intent_hash).await {
                    if tx_ids.user_to_network_tx_id.is_some() {
                        continue;
                    }
                }

                // intent.timestamp is Unix seconds (u128) or conditionally evaluated as milliseconds
                let mut intent_timestamp = intent.timestamp;
                if intent_timestamp > 1_000_000_000_000 {
                    intent_timestamp /= 1000;
                }
                let age_secs = now_secs.saturating_sub(intent_timestamp);
                if age_secs >= max_age_secs as u128 {
                    info!(
                        "⏰ [STALE_INTENT] Rejecting stale intent {} for user {} — status {:?}, age {}s (>{} max)",
                        intent_hash, tics_address, status, age_secs, max_age_secs
                    );
                    if let Err(e) = self
                        .update_intent_status(tics_address, intent_hash, IntentStatus::Rejected)
                        .await
                    {
                        warn!(
                            "⚠️ [STALE_INTENT] Failed to reject stale intent {}: {}",
                            intent_hash, e
                        );
                    } else {
                        rejected_count += 1;
                    }
                }
            }
        }

        if rejected_count > 0 {
            info!(
                "⏰ [STALE_INTENT] Rejected {} stale Pending/Batched intents (max age: {}s)",
                rejected_count, max_age_secs
            );
        }

        rejected_count
    }
}
