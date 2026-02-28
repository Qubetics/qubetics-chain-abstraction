use super::*;
use anyhow::{anyhow, Result};
use hex;
use sha3::Digest;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
pub use chains::{BitcoinSigner, TicsSigner};
pub use config::{BroadcastConfig, ChainBroadcastConfig};
pub use coordination::Coordination;
pub use db_signing::DatabaseSigningNode;
pub use key::KeyStore;
pub use state::{
    BroadcastPolicy, BtcAggregationState, BtcRoundExtras, BtcUtvAggregationState, PendingStore,
    PendingValue, RoundSlotKey, SignatureStore, SigningEnvironmentBuilder,
};
pub use nonce::{NonceGenerator, NonceManager};
use crate::types::{
    ChannelMessage,
    TransactionType,
};
use crate::user_intent_manager::UserIntentManager;

impl SigningNode {
    /// Pick pending BTC platform-fee claim requests and broadcast BtcClaimPlatformFeeBatch (called from epoch_4).
    pub(crate) async fn process_btc_claim_platform_fee_batch_for_round(&self, round: u64) -> Result<()> {
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        let all_claims: Vec<(String, crate::types::rpc_server::PendingClaimPlatformFeeRequest)> =
            db.get_values_with_prefix(crate::database::primitives::keys::PENDING_CLAIM_PLATFORM_FEE)
                .map_err(|e| anyhow!("Failed to load pending claim platform fee requests: {}", e))?;

        // Revert stale "Batched" BTC claims (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous BTC signing round failed silently.
        for (key, req) in &all_claims {
            if req.asset == "BTC" && req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [BTC_CLAIM_PLATFORM_FEE] Failed to revert stale Batched claim {} to Pending: {}", req.request_id, e);
                } else {
                    info!("🔄 [BTC_CLAIM_PLATFORM_FEE] Reverted stale Batched claim {} (no tx_id) back to Pending for retry", req.request_id);
                }
            }
        }

        let btc_claim_pending: Vec<_> = all_claims
            .into_iter()
            .filter(|(_, req)| {
                req.asset == "BTC"
                    && (req.status == "Pending" || req.status == "Batched")
                    && req.tx_id.is_none()
                    && req.btc_target_address.as_ref().map_or(false, |a| !a.trim().is_empty())
            })
            .collect();

        if btc_claim_pending.is_empty() {
            return Ok(());
        }

        // Platform fee: only one request at a time per chain, so take the first one
        let (ref db_key, ref req) = btc_claim_pending[0];
        let claim_requests: Vec<(String, String)> = vec![(
            req.request_id.clone(),
            req.btc_target_address.clone().unwrap_or_default(),
        )];

        // Mark as Batched to prevent re-picking in subsequent epoch_4 rounds
        let mut updated_req = req.clone();
        updated_req.status = "Batched".to_string();
        if let Err(e) = db.put_string(db_key, &updated_req) {
            warn!("⚠️ [BTC_CLAIM_PLATFORM_FEE] Failed to mark claim {} as Batched: {}", req.request_id, e);
        } else {
            info!("📝 [BTC_CLAIM_PLATFORM_FEE] Marked claim {} as Batched", req.request_id);
        }

        use crate::signing::chains::bitcoin_batch::BatchOutput;

        let mut batch_outputs: Vec<BatchOutput> = Vec::new();
        let amount_sats: u64 = match req.amount.parse() {
            Ok(amt) if amt >= 546 => amt,
            Ok(_) => {
                warn!("⚠️ [BTC_CLAIM_PLATFORM_FEE] Request {} amount below dust threshold", req.request_id);
                return Ok(());
            }
            Err(e) => {
                warn!("⚠️ [BTC_CLAIM_PLATFORM_FEE] Invalid amount for request {}: {}", req.request_id, e);
                return Ok(());
            }
        };
        batch_outputs.push(BatchOutput {
            address: req.btc_target_address.clone().unwrap_or_default(),
            amount: amount_sats,
        });

        let claim_batch_timestamp = chrono::Utc::now().to_rfc3339();
        let claim_batch_id = format!(
            "btc_claim_platform_fee_batch:{}:{}",
            round,
            chrono::Utc::now().timestamp_millis()
        );

        let total_inputs = match self
            .compute_btc_unsigned_input_count_from_outputs(batch_outputs)
            .await
        {
            Ok(count) if count > 0 => count,
            Ok(_) => {
                tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] Computed unsigned tx with zero inputs for batch {} - aborting (will retry next epoch)", claim_batch_id);
                return Ok(());
            }
            Err(e) => {
                tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] Failed to precompute unsigned BTC platform-fee tx for batch {}: {} - aborting (will retry next epoch)", claim_batch_id, e);
                return Ok(());
            }
        };

        let reservation_keys: Vec<String> = (0..total_inputs)
            .map(|i| format!("{}_{}", claim_batch_id, i))
            .collect();

        let nonce_tuple_ids = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&reservation_keys).await {
                Ok(assignments) => {
                    if assignments.len() < reservation_keys.len() {
                        tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] Reserved only {} of {} required nonces for batch {} - aborting (will retry next epoch)", assignments.len(), reservation_keys.len(), claim_batch_id);
                        return Ok(());
                    }

                    let mut ordered = Vec::with_capacity(reservation_keys.len());
                    for key in &reservation_keys {
                        if let Some(tuple_id) = assignments.get(key) {
                            ordered.push(tuple_id.clone());
                        } else {
                            tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] Missing nonce assignment for key {} in batch {} - aborting (will retry next epoch)", key, claim_batch_id);
                            return Ok(());
                        }
                    }
                    ordered
                }
                Err(e) => {
                    tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] Failed to reserve nonces for batch {}: {} - aborting (will retry next epoch)", claim_batch_id, e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] NonceManager not available - aborting batch (will retry next epoch)");
            return Ok(());
        };

        info!(
            "📤 [CLOCK][BTC_CLAIM_PLATFORM_FEE] Broadcasting BTC claim-platform-fee batch {} with {} requests ({} ordered nonces)",
            claim_batch_id,
            claim_requests.len(),
            nonce_tuple_ids.len()
        );
        self.message_tx
            .send(crate::types::ChannelMessage::BtcClaimPlatformFeeBatch {
                batch_id: claim_batch_id,
                requests: claim_requests,
                round,
                timestamp: claim_batch_timestamp,
                node_id: self.id.clone(),
                nonce_tuple_ids: Some(nonce_tuple_ids),
            })
            .await
            .map_err(|e| anyhow!("Failed to send BtcClaimPlatformFeeBatch: {}", e))?;

        Ok(())
    }

    /// Trigger BTC contract update round in parallel to BTC batch transfer round
    /// This ONLY triggers selection - the final node will:
    /// 1. Get intents with network_to_target_tx_id but not Solved
    /// 2. Create batch and broadcast via btc-intent-manager-tx-update
    /// 3. All nodes will process the batch and participate in MPC signing
    pub(crate) async fn trigger_btc_contract_update_round_parallel(&mut self) -> Result<()> {
        info!("🔄 [BTC_CONTRACT_UPDATE] Starting parallel contract update round trigger");

        // Get available nodes
        let available_nodes: Vec<libp2p::PeerId> = self
            .coordination
            .get_available_nodes()
            .await;

        if available_nodes.is_empty() {
            warn!("⚠️ [BTC_CONTRACT_UPDATE] No available nodes for selection");
            return Ok(());
        }

        // Get next round in a block so we can release vrf_service borrow before replicate_vrf_round_to_consensus
        let contract_update_round = {
            let vrf_service = self.coordination
                .vrf_service()
                .ok_or_else(|| anyhow!("Round/selection service not available"))?;
            if let Err(e) = vrf_service.sync_rounds_before_signing().await {
                warn!("⚠️ [BTC_CONTRACT_UPDATE] Failed to sync rounds: {}", e);
            }
            vrf_service.get_next_round().await
        };
        self.replicate_vrf_round_to_consensus(contract_update_round);

        info!(
            "🎯 [BTC_CONTRACT_UPDATE] Performing selection for contract update round {} (parallel to BTC batch round)",
            contract_update_round
        );

        // Perform node selection for BTC intent manager update round
        let vrf_service = self.coordination
            .vrf_service()
            .ok_or_else(|| anyhow!("Round/selection service not available"))?;
        match vrf_service
            .perform_node_selection(
                &available_nodes,
                crate::vrf::VRF_NODE_SELECTION_COUNT,
                contract_update_round,
                "btc_intent_manager_update",
            )
            .await
        {
            Ok(_selection_result) => {
                info!(
                    "✅ [BTC_CONTRACT_UPDATE] Selection completed for round {}. Final node will select eligible intents and broadcast batch.",
                    contract_update_round
                );
            }
            Err(e) => {
                error!("❌ [BTC_CONTRACT_UPDATE] Selection failed: {}", e);
                return Err(e);
            }
        }

        // The round will proceed to consensus, and the final node will:
        // 1. Get eligible intents (network_to_target_tx_id, NOT Solved, BTC target chain)
        // 2. Create BtcIntentManagerTxUpdate message
        // 3. Broadcast to all nodes via gossipsub
        // 4. All nodes will process the batch and participate in MPC signing for the contract call

        Ok(())
    }

    /// Process BTC contract update batch when final node is selected for contract update round
    /// This function is called by the FINAL NODE after consensus completes for btc_contract_update round.
    /// The final node will:
    /// 1. Get eligible intents (network_to_target_tx_id exists, status NOT Solved, BTC target chain)
    /// 2. Create BtcIntentManagerTxUpdate message with intent hashes
    /// 3. Broadcast to all nodes via gossipsub
    /// 4. All nodes will receive the batch and participate in MPC signing for the contract call
    pub(crate) async fn process_btc_contract_update_batch_for_round(&self, round: u64) -> Result<()> {
        info!("🔄 [BTC_CONTRACT_UPDATE] Processing contract update batch for round {}", round);

        // Get user intent manager
        let user_intent_manager = self.user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        // Get database to access IntentStorage directly
        let database = user_intent_manager.get_database();
        let intent_storage = crate::database::storage::IntentStorage::new(database.clone());

        // Get intents with BOTH user_to_network_tx_id AND network_to_target_tx_id (completed intents)
        let completed_intents = intent_storage.get_completed_intents().await?;

        // Filter: must be BTC target chain AND status NOT Solved
        let mut eligible_intents = Vec::new();
        for (intent_hash, intent, tx_ids) in completed_intents {
            // Must be BTC target chain
            let target_chain_lower = intent.target_chain.to_lowercase();
            if target_chain_lower != "bitcoin" && target_chain_lower != "btc" {
                continue;
            }

            // Check if intent status is NOT Solved
            if let Some(user) = user_intent_manager
                .get_user_by_intent_hash(&intent_hash)
                .await
            {
                if let Some(status) = user.intent_hashes.get(&intent_hash) {
                    if *status == crate::types::IntentStatus::Solved {
                        continue; // Skip solved intents
                    }
                }
            }

            eligible_intents.push((intent_hash, intent, tx_ids));
        }

        if eligible_intents.is_empty() {
            info!(
                "ℹ️ [BTC_CONTRACT_UPDATE] No eligible intents found for contract update batch"
            );
            return Ok(());
        }

        info!(
            "📋 [BTC_CONTRACT_UPDATE] Found {} eligible intents for contract update batch",
            eligible_intents.len()
        );

        // Prepare intent hashes for the batch
        let intent_hashes: Vec<String> = eligible_intents
            .iter()
            .map(|(hash, _, _)| hash.clone())
            .collect();

        // Create batch timestamp
        let batch_timestamp = chrono::Utc::now().to_rfc3339();
        let intent_fingerprint = {
            let mut hasher = sha3::Keccak256::new();
            hasher.update(intent_hashes.join(",").as_bytes());
            hex::encode(&hasher.finalize()[..8])
        };

        // Reserve a nonce for this batch BEFORE broadcasting (coordinator responsibility)
        // SECURITY: Nonces are REQUIRED - abort batch if unavailable
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let reservation_key = format!(
                "btc_contract_update:round:{}:batch:{}:intent_fp:{}",
                round, batch_timestamp, intent_fingerprint
            );
            let nm_guard = nm.lock().await;
            match nm_guard
                .reserve_nonces_for_batch(std::slice::from_ref(&reservation_key))
                .await
            {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get(&reservation_key) {
                        info!(
                            "🔐 [BTC_CONTRACT_UPDATE] Reserved nonce tuple assignment reservation_key={} tuple_id={}",
                            reservation_key,
                            tuple_id
                        );
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [BTC_CONTRACT_UPDATE] No nonce assigned - aborting batch (will retry next cycle)");
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [BTC_CONTRACT_UPDATE] Failed to reserve nonce: {} - aborting batch (will retry next cycle)", e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [BTC_CONTRACT_UPDATE] NonceManager not available - aborting batch (will retry next cycle)");
            return Ok(());
        };

        // Broadcast via btc-intent-manager-tx-update topic
        // Note: We don't have the BTC batch txid yet since it's happening in parallel
        // The contract update handler will need to wait for the BTC batch to complete
        // or process with existing network_to_target_tx_id values
        let batch_message = crate::types::ChannelMessage::BtcIntentManagerTxUpdate {
            intent_hashes: intent_hashes.clone(),
            btc_txid: "pending".to_string(), // Will be updated when BTC batch completes
            btc_batch_round: 0, // Will be set when BTC batch completes
            update_round: round,
            timestamp: batch_timestamp,
            node_id: self.id.clone(),
            nonce_tuple_ids: Some(vec![nonce_tuple_id]),
        };

        self.message_tx
            .send(batch_message)
            .await
            .map_err(|e| anyhow!("Failed to send BTC intent manager update message: {}", e))?;

        info!(
            "✅ [BTC_CONTRACT_UPDATE] Broadcasted contract update batch with {} intents (round {})",
            intent_hashes.len(),
            round
        );

        Ok(())
    }

    /// Process pending solver_add_liquidity requests in batch
    /// Called by the final node selected via global_clock round.
    /// The final node will:
    /// 1. Query RocksDB for pending add_liquidity requests (status="Pending", age >= 10s)
    /// 2. Sort by timestamp (oldest first), limit to MAX_ADD_LIQUIDITY_BATCH
    /// 3. Atomically mark selected requests as "Batched" in RocksDB
    /// 4. Broadcast the batch via ChannelMessage::SolverAddLiquidityBatch
    /// 5. All nodes will verify, generate partial signatures (liquidity_operator key)
    /// 6. Final node aggregates and submits batchTransfer tx to contract
    pub(crate) async fn process_solver_add_liquidity_batch_for_round(&self, round: u64) -> Result<()> {
        info!("💧 [ADD_LIQUIDITY] Processing solver_add_liquidity batch for round {}", round);

        // Get database reference
        let database = self.database.as_ref()
            .ok_or_else(|| anyhow!("Database not available"))?;

        let max_batch_size = crate::env_defaults::max_add_liquidity_batch();

        let min_age_seconds = 10; // Minimum age in seconds before batching

        // Query all pending add_liquidity requests from RocksDB
        const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";
        
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        struct PendingAddLiquidityRecord {
            request_id: String,
            solver_id: String,
            solver_address: String,
            amount: String,
            chain_id: u64,
            signature: String,
            signed_payload: String,
            timestamp_ms: i64,
            status: String,
            #[serde(default)]
            tx_id: Option<String>,
        }

        // Scan RocksDB for all keys with the prefix (async wrapper)
        let all_keys = database
            .get_keys_with_prefix_async(ADD_LIQUIDITY_DB_PREFIX)
            .await?;
        
        let mut pending_requests = Vec::new();
        let now_ms = chrono::Utc::now().timestamp_millis();

        for key in all_keys {
            if let Ok(Some(record)) = database
                .get_string_async::<PendingAddLiquidityRecord>(&key)
                .await
            {
                // Filter: status must be "Pending" and age >= min_age_seconds
                if record.status == "Pending" {
                    let age_ms = now_ms - record.timestamp_ms;
                    let age_secs = age_ms / 1000;
                    
                    if age_secs >= min_age_seconds {
                        pending_requests.push((key, record));
                    }
                }
            }
        }

        if pending_requests.is_empty() {
            info!("ℹ️  [ADD_LIQUIDITY] No pending requests eligible for batching (age >= {}s)", min_age_seconds);
            return Ok(());
        }

        // Sort by timestamp (oldest first)
        pending_requests.sort_by(|a, b| a.1.timestamp_ms.cmp(&b.1.timestamp_ms));

        // Limit to max_batch_size
        let requests_to_batch: Vec<_> = pending_requests
            .into_iter()
            .take(max_batch_size)
            .collect();

        info!(
            "📋 [ADD_LIQUIDITY] Selected {} requests for batching (max: {}, min_age: {}s)",
            requests_to_batch.len(),
            max_batch_size,
            min_age_seconds
        );

        // Keep all selected requests as "Pending" - they will be marked "Completed" on success
        info!(
            "📦 [ADD_LIQUIDITY] Selected {} requests for batching (keeping status as 'Pending')",
            requests_to_batch.len()
        );

        // Prepare batch data for broadcast
        let batch_entries: Vec<(String, String, String, u64)> = requests_to_batch
            .iter()
            .map(|(_, record)| {
                (
                    record.request_id.clone(),
                    record.solver_address.clone(),
                    record.amount.clone(),
                    record.chain_id,
                )
            })
            .collect();

        // Broadcast the batch to all nodes via ChannelMessage
        let batch_timestamp = chrono::Utc::now().to_rfc3339();

        // Reserve a nonce for this batch BEFORE broadcasting (coordinator responsibility)
        // SECURITY: Nonces are REQUIRED - abort batch if unavailable
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let request_fingerprint = {
                let mut hasher = sha3::Keccak256::new();
                hasher.update(
                    batch_entries
                        .iter()
                        .map(|(request_id, _, _, _)| request_id.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                        .as_bytes(),
                );
                hex::encode(&hasher.finalize()[..8])
            };
            let reservation_key = format!(
                "add_liquidity_batch:round:{}:batch:{}:request_fp:{}",
                round,
                batch_timestamp,
                request_fingerprint
            );
            let nm_guard = nm.lock().await;
            match nm_guard
                .reserve_nonces_for_batch(std::slice::from_ref(&reservation_key))
                .await
            {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get(&reservation_key) {
                        info!(
                            "🔐 [ADD_LIQUIDITY] Reserved nonce tuple assignment reservation_key={} tuple_id={}",
                            reservation_key,
                            tuple_id
                        );
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [ADD_LIQUIDITY] No nonce assigned - aborting batch (will retry next epoch)");
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [ADD_LIQUIDITY] Failed to reserve nonce: {} - aborting batch (will retry next epoch)", e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [ADD_LIQUIDITY] NonceManager not available - aborting batch (will retry next epoch)");
            return Ok(());
        };

        // Only send request_ids - all nodes have the full records in RocksDB
        let batch_message = ChannelMessage::SolverAddLiquidityBatch {
            request_ids: batch_entries.iter().map(|(id, _, _, _)| id.clone()).collect(),
            round,
            timestamp: batch_timestamp.clone(),
            node_id: self.id.clone(),
            nonce_tuple_id: Some(nonce_tuple_id),
        };

        self.message_tx
            .send(batch_message)
            .await
            .map_err(|e| anyhow!("Failed to send SolverAddLiquidityBatch message: {}", e))?;

        info!(
            "✅ [ADD_LIQUIDITY] Broadcasted batch with {} requests for round {} at {}",
            batch_entries.len(),
            round,
            batch_timestamp
        );

        // Log details of each request in the batch
        for (_key, record) in &requests_to_batch {
            let wait_duration_secs = (now_ms - record.timestamp_ms) / 1000;
            info!(
                "  💧 [BATCH] Request {}: solver={}, amount={}, chain={}, waiting={}s",
                record.request_id,
                record.solver_address,
                record.amount,
                record.chain_id,
                wait_duration_secs
            );
        }

        Ok(())
    }

    /// Epoch 3: Withdraw settlement / cleanup.
    /// This epoch does NOT create new transactions; it finalizes the logical status
    /// of withdraw-liquidity requests so they are not picked again in future epochs.
    /// Rules:
    /// - For TICS: Pending requests are batched into a TICS withdraw batch
    ///   and marked as "Batched". The actual completion happens once the
    ///   removeLiquidity contract transaction is mined and tx_id is stored.
    /// - For BTC: any PendingWithdrawRequest with asset="BTC", status="Pending",
    ///   and a non-empty tx_id is also marked status="Completed".
    pub(crate) async fn process_withdraw_settlement_epoch(&self, round: u64) -> Result<()> {
        use crate::types::rpc_server::PendingWithdrawRequest;
        use crate::types::messaging::TicsWithdrawBatchRequest;

        info!("🔍 [CLOCK] Processing withdraw settlement epoch (epoch_3)...");

        // Get user intent manager and backing database
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        // Load all pending withdraw requests across all solvers
        let all_withdraws: Vec<(String, PendingWithdrawRequest)> =
            match db.get_values_with_prefix("pending_withdraw_liquidity:") {
                Ok(entries) => entries,
                Err(e) => {
                    warn!(
                        "⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to load pending withdraw requests: {}",
                        e
                    );
                    return Ok(());
                }
            };

        if all_withdraws.is_empty() {
            info!(
                "ℹ️  [CLOCK][WITHDRAW_SETTLE] No withdraw requests found for settlement epoch"
            );
            return Ok(());
        }

        // Revert stale "Batched" withdraw requests (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous signing round failed.
        for (key, req) in &all_withdraws {
            if req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to revert stale Batched {} withdraw {} to Pending: {}", req.asset, req.request_id, e);
                } else {
                    info!("🔄 [CLOCK][WITHDRAW_SETTLE] Reverted stale Batched {} withdraw {} (no tx_id) back to Pending for retry", req.asset, req.request_id);
                }
            }
        }

        let mut tics_batched = 0usize;
        let mut btc_updated = 0usize;

        let mut tics_batch_requests: Vec<TicsWithdrawBatchRequest> = Vec::new();

        for (key, mut req) in all_withdraws {
            if req.status != "Pending" {
                continue;
            }

            let asset_upper = req.asset.to_uppercase();

            // TICS: pick all Pending requests for settlement batch, mark as "Batched"
            if asset_upper == "TICS" {
                // Build batch metadata from the current record
                tics_batch_requests.push(TicsWithdrawBatchRequest {
                    request_id: req.request_id.clone(),
                    solver_address: req.solver_address.clone(),
                    asset: req.asset.clone(),
                    amount: req.amount.clone(),
                    // TICS withdraws are executed on the main TICS EVM chain (chain ID from SOLVER_CONTRACT_CHAIN_ID env var).
                    chain_id: crate::env_defaults::solver_contract_chain_id()
                        .parse::<u64>()
                        .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id()),
                    tx_id: req.tx_id.clone(),
                });

                req.status = "Batched".to_string();
                if let Err(e) = db.put_string(&key, &req) {
                    warn!(
                        "⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to mark TICS withdraw {} as Batched: {}",
                        req.request_id, e
                    );
                } else {
                    tics_batched += 1;
                }
                continue;
            }

            // BTC: pick Pending requests that already have an on-chain tx_id so they get
            // registered on the contract in the same TICS withdraw batch (funds already sent).
            let has_tx_id = req.tx_id.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
            if asset_upper == "BTC" && has_tx_id {
                tics_batch_requests.push(TicsWithdrawBatchRequest {
                    request_id: req.request_id.clone(),
                    solver_address: req.solver_address.clone(),
                    asset: req.asset.clone(),
                    amount: req.amount.clone(),
                    chain_id: 0, // BTC
                    tx_id: req.tx_id.clone(),
                });

                req.status = "Batched".to_string();
                if let Err(e) = db.put_string(&key, &req) {
                    warn!(
                        "⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to mark BTC withdraw {} as Batched: {}",
                        req.request_id, e
                    );
                } else {
                    btc_updated += 1;
                }
            }
        }

        // If we have any TICS withdraws to settle, broadcast a TICS withdraw batch
        if !tics_batch_requests.is_empty() {
            let batch_timestamp = chrono::Utc::now().to_rfc3339();
            let batch_id = format!(
                "tics_withdraw_batch:{}:{}",
                round,
                chrono::Utc::now().timestamp_millis()
            );

            info!(
                "📦 [CLOCK][WITHDRAW_SETTLE] Creating TICS withdraw batch {} with {} requests for round {}",
                batch_id,
                tics_batch_requests.len(),
                round
            );

            // Reserve a single nonce for this batch signing
            // SECURITY: Nonces are REQUIRED - abort batch if unavailable
            // NOTE: Use reserve_nonces_for_batch() NOT acquire_nonce() - the coordinator must NOT
            // consume the nonce, only reserve it. Each node consumes their own copy when signing.
            let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
                let nm_guard = nm.lock().await;
                match nm_guard.reserve_nonces_for_batch(&[batch_id.clone()]).await {
                    Ok(assignments) => {
                        if let Some(tuple_id) = assignments.get(&batch_id) {
                            info!("🔐 [WITHDRAW_SETTLE] Reserved nonce {} for batch {}", tuple_id, batch_id);
                            tuple_id.clone()
                        } else {
                            tracing::error!("🔴 [WITHDRAW_SETTLE] No nonce assignment returned for batch {} - aborting batch (will retry next epoch)", batch_id);
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::error!("🔴 [WITHDRAW_SETTLE] Failed to reserve nonce for batch {}: {} - aborting batch (will retry next epoch)", batch_id, e);
                        return Ok(());
                    }
                }
            } else {
                tracing::error!("🔴 [WITHDRAW_SETTLE] NonceManager not available - aborting batch (will retry next epoch)");
                return Ok(());
            };

            let message = ChannelMessage::TicsWithdrawBatch {
                batch_id,
                requests: tics_batch_requests,
                round,
                timestamp: batch_timestamp,
                node_id: self.id.clone(),
                nonce_tuple_ids: Some(vec![nonce_tuple_id]),
            };

            if let Err(e) = self.message_tx.send(message).await {
                warn!(
                    "⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to send TicsWithdrawBatch channel message: {}",
                    e
                );
            }
        }

        info!(
            "✅ [CLOCK][WITHDRAW_SETTLE] Settlement epoch completed: {} TICS withdraws batched, {} BTC withdraws (with tx_id) batched for contract registration",
            tics_batched, btc_updated
        );

        Ok(())
    }

    /// TICS claim-reward settlement (same flow as withdraw settlement).
    /// Picks TICS claim requests (pending, have tics_address) and BTC claim requests (pending, have tx_id) for contract.
    /// On success: store TICS tx_id on TICS requests and mark done; mark BTC requests done only.
    pub(crate) async fn process_tics_claim_reward_settlement_epoch(&self, round: u64) -> Result<()> {
        use crate::types::messaging::TicsClaimRewardBatchRequest;
        use crate::types::rpc_server::PendingClaimRewardRequest;

        info!("🔍 [CLOCK] Processing TICS claim-reward settlement epoch (epoch_3)...");

        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        let all_claims: Vec<(String, PendingClaimRewardRequest)> =
            match db.get_values_with_prefix("pending_claim_reward:") {
                Ok(entries) => entries,
                Err(e) => {
                    warn!(
                        "⚠️ [CLOCK][TICS_CLAIM] Failed to load pending claim reward requests: {}",
                        e
                    );
                    return Ok(());
                }
            };

        if all_claims.is_empty() {
            info!(
                "ℹ️  [CLOCK][TICS_CLAIM] No claim reward requests found for settlement epoch"
            );
            return Ok(());
        }

        // Revert stale "Batched" claim reward requests (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous signing round failed.
        for (key, req) in &all_claims {
            if req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [CLOCK][TICS_CLAIM] Failed to revert stale Batched claim {} to Pending: {}", req.request_id, e);
                } else {
                    info!("🔄 [CLOCK][TICS_CLAIM] Reverted stale Batched claim {} (no tx_id) back to Pending for retry", req.request_id);
                }
            }
        }

        let tics_chain_id = crate::env_defaults::solver_contract_chain_id()
            .parse::<u64>()
            .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());

        let mut tics_batched = 0usize;
        let mut btc_updated = 0usize;
        let mut tics_claim_batch_requests: Vec<TicsClaimRewardBatchRequest> = Vec::new();

        for (key, mut req) in all_claims {
            if req.status != "Pending" {
                continue;
            }

            // TICS: pick pending requests that have tics_address (claim TICS to that address)
            let has_eth = req.tics_address.as_ref().map_or(false, |a| !a.trim().is_empty());
            if has_eth {
                tics_claim_batch_requests.push(TicsClaimRewardBatchRequest {
                    request_id: req.request_id.clone(),
                    solver_address: req.solver_address.clone(),
                    asset: "TICS".to_string(),
                    amount: "0".to_string(), // gossipsub will fetch from contract
                    chain_id: tics_chain_id,
                    tx_id: req.tx_id.clone(),
                });
                req.status = "Batched".to_string();
                if let Err(e) = db.put_string(&key, &req) {
                    warn!(
                        "⚠️ [CLOCK][TICS_CLAIM] Failed to mark TICS claim {} as Batched: {}",
                        req.request_id, e
                    );
                } else {
                    tics_batched += 1;
                }
                continue;
            }

            // BTC: pick pending requests that already have tx_id (register on contract in same batch)
            let has_tx_id = req.tx_id.as_ref().map_or(false, |s| !s.is_empty());
            let has_btc = req.btc_address.as_ref().map_or(false, |a| !a.trim().is_empty());
            if has_btc && has_tx_id {
                tics_claim_batch_requests.push(TicsClaimRewardBatchRequest {
                    request_id: req.request_id.clone(),
                    solver_address: req.solver_address.clone(),
                    asset: "BTC".to_string(),
                    amount: "0".to_string(),
                    chain_id: 0,
                    tx_id: req.tx_id.clone(),
                });
                req.status = "Batched".to_string();
                if let Err(e) = db.put_string(&key, &req) {
                    warn!(
                        "⚠️ [CLOCK][TICS_CLAIM] Failed to mark BTC claim {} as Batched: {}",
                        req.request_id, e
                    );
                } else {
                    btc_updated += 1;
                }
            }
        }

        if !tics_claim_batch_requests.is_empty() {
            let batch_timestamp = chrono::Utc::now().to_rfc3339();
            let batch_id = format!(
                "tics_claim_reward_batch:{}:{}",
                round,
                chrono::Utc::now().timestamp_millis()
            );

            info!(
                "📦 [CLOCK][TICS_CLAIM] Creating TICS claim-reward batch {} with {} requests for round {}",
                batch_id,
                tics_claim_batch_requests.len(),
                round
            );

            // Reserve a single nonce for this batch signing
            // SECURITY: Nonces are REQUIRED - abort batch if unavailable
            // NOTE: Use reserve_nonces_for_batch() NOT acquire_nonce() - the coordinator must NOT
            // consume the nonce, only reserve it. Each node consumes their own copy when signing.
            let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
                let nm_guard = nm.lock().await;
                match nm_guard.reserve_nonces_for_batch(&[batch_id.clone()]).await {
                    Ok(assignments) => {
                        if let Some(tuple_id) = assignments.get(&batch_id) {
                            info!("🔐 [TICS_CLAIM] Reserved nonce {} for batch {}", tuple_id, batch_id);
                            tuple_id.clone()
                        } else {
                            tracing::error!("🔴 [TICS_CLAIM] No nonce assignment returned for batch {} - aborting batch (will retry next epoch)", batch_id);
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::error!("🔴 [TICS_CLAIM] Failed to reserve nonce for batch {}: {} - aborting batch (will retry next epoch)", batch_id, e);
                        return Ok(());
                    }
                }
            } else {
                tracing::error!("🔴 [TICS_CLAIM] NonceManager not available - aborting batch (will retry next epoch)");
                return Ok(());
            };

            let message = ChannelMessage::TicsClaimRewardBatch {
                batch_id,
                requests: tics_claim_batch_requests,
                round,
                timestamp: batch_timestamp,
                node_id: self.id.clone(),
                nonce_tuple_ids: Some(vec![nonce_tuple_id]),
            };

            if let Err(e) = self.message_tx.send(message).await {
                warn!(
                    "⚠️ [CLOCK][TICS_CLAIM] Failed to send TicsClaimRewardBatch channel message: {}",
                    e
                );
            }
        }

        info!(
            "✅ [CLOCK][TICS_CLAIM] Settlement epoch completed: {} TICS claim requests batched, {} BTC claim requests (with tx_id) batched for contract",
            tics_batched, btc_updated
        );

        Ok(())
    }

    /// TICS platform-fee claim settlement: picks one eligible platform-fee claim (TICS-first, then BTC-with-txid),
    /// builds a claimPlatformFee contract transaction signed by the admin's MPC-derived key, and broadcasts for signing.
    pub(crate) async fn process_tics_claim_platform_fee_settlement_epoch(&self, round: u64) -> Result<()> {
        use crate::types::messaging::TicsClaimPlatformFeeBatchRequest;
        use crate::types::rpc_server::PendingClaimPlatformFeeRequest;

        info!("🔍 [CLOCK] Processing TICS claim-platform-fee settlement epoch (epoch_3)...");

        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        // Load all pending platform fee claims from DB
        let all_claims: Vec<(String, PendingClaimPlatformFeeRequest)> =
            match db.get_values_with_prefix("pending_claim_platform_fee:") {
                Ok(entries) => entries,
                Err(e) => {
                    warn!("⚠️ [CLOCK][TICS_PF] Failed to load pending platform fee claims: {}", e);
                    return Ok(());
                }
            };

        if all_claims.is_empty() {
            info!("ℹ️  [CLOCK][TICS_PF] No platform fee claims found for settlement epoch");
            return Ok(());
        }

        // Look up admin registration to get admin_tics_address for the batch request
        let admin_public_address = crate::env_defaults::admin_public_address();
        if admin_public_address.trim().is_empty() {
            warn!("⚠️ [CLOCK][TICS_PF] ADMIN_PUBLIC_ADDRESS not configured; skipping platform fee settlement");
            return Ok(());
        }
        let admin_reg = match user_intent_manager
            .get_admin_by_address(&admin_public_address)
            .await
        {
            Some(reg) => reg,
            None => {
                warn!("⚠️ [CLOCK][TICS_PF] Admin not registered ({}); skipping", admin_public_address);
                return Ok(());
            }
        };
        if admin_reg.derived_eth_address.is_none() || admin_reg.tweaked_secret_share.is_none() {
            warn!("⚠️ [CLOCK][TICS_PF] Admin missing derived_eth_address or tweaked_secret_share; skipping");
            return Ok(());
        }

        // Revert stale "Batched" TICS claims (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous TICS signing round failed.
        for (key, req) in &all_claims {
            if req.asset == "TICS" && req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [CLOCK][TICS_PF] Failed to revert stale Batched TICS claim {} to Pending: {}", req.request_id, e);
                } else {
                    info!("🔄 [CLOCK][TICS_PF] Reverted stale Batched TICS claim {} (no tx_id) back to Pending for retry", req.request_id);
                }
            }
        }

        // Pick first eligible claim: TICS first, then BTC-with-txid
        let mut selected: Option<(String, PendingClaimPlatformFeeRequest)> = None;

        // Priority 1: TICS claims
        for (key, req) in &all_claims {
            if req.status == "Pending" && req.asset == "TICS" {
                selected = Some((key.clone(), req.clone()));
                break;
            }
        }

        // Priority 2: BTC claims with tx_id (need on-chain registration)
        // Accept both "Pending" (legacy) and "Batched" (after BTC transfer epoch marked it Batched)
        if selected.is_none() {
            for (key, req) in &all_claims {
                if (req.status == "Pending" || req.status == "Batched")
                    && req.asset == "BTC"
                    && req.tx_id.as_ref().map_or(false, |t| !t.is_empty())
                {
                    selected = Some((key.clone(), req.clone()));
                    break;
                }
            }
        }

        let (db_key, mut req) = match selected {
            Some(s) => s,
            None => {
                info!("ℹ️  [CLOCK][TICS_PF] No eligible platform fee claims for TICS settlement");
                return Ok(());
            }
        };

        let chain_type: u8 = if req.asset == "TICS" { 1 } else { 0 };
        // For TICS claims: recipient = tics_target_address (the actual receiver on TICS chain)
        // For BTC claims: recipient = admin's derived_eth_address (BTC already sent to btc_target_address
        //   in epoch_4; this contract call just updates on-chain accounting)
        let target_address = if req.asset == "TICS" {
            req.tics_target_address.clone().unwrap_or_default()
        } else {
            // BTC: use admin's derived EVM address for the contract call recipient
            admin_reg.derived_eth_address.clone().unwrap_or_default()
        };

        if target_address.is_empty() {
            warn!("⚠️ [CLOCK][TICS_PF] No target address for claim {}; skipping", req.request_id);
            return Ok(());
        }

        let batch_request = TicsClaimPlatformFeeBatchRequest {
            request_id: req.request_id.clone(),
            asset: req.asset.clone(),
            amount: req.amount.clone(),
            chain_type,
            tx_id: req.tx_id.clone(),
            target_address,
            admin_tics_address: admin_reg.tics_address.clone(),
        };

        // Mark as Batched
        req.status = "Batched".to_string();
        if let Err(e) = db.put_string(&db_key, &req) {
            warn!("⚠️ [CLOCK][TICS_PF] Failed to mark claim {} as Batched: {}", req.request_id, e);
        }

        let batch_timestamp = chrono::Utc::now().to_rfc3339();
        let batch_id = format!(
            "tics_claim_platform_fee_batch:{}:{}",
            round,
            chrono::Utc::now().timestamp_millis()
        );

        info!(
            "📦 [CLOCK][TICS_PF] Creating TICS platform-fee batch {} for {} claim (request_id={}) at round {}",
            batch_id, req.asset, req.request_id, round
        );

        // Reserve nonce
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard
                .reserve_nonces_for_batch(&[batch_id.clone()])
                .await
            {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get(&batch_id) {
                        info!("🔐 [TICS_PF] Reserved nonce {} for batch {}", tuple_id, batch_id);
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [TICS_PF] No nonce assignment for batch {} - aborting", batch_id);
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [TICS_PF] Failed to reserve nonce for batch {}: {} - aborting", batch_id, e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [TICS_PF] NonceManager not available - aborting");
            return Ok(());
        };

        let message = ChannelMessage::TicsClaimPlatformFeeBatch {
            batch_id,
            requests: vec![batch_request],
            round,
            timestamp: batch_timestamp,
            node_id: self.id.clone(),
            nonce_tuple_id: Some(nonce_tuple_id),
        };

        if let Err(e) = self.message_tx.send(message).await {
            warn!(
                "⚠️ [CLOCK][TICS_PF] Failed to send TicsClaimPlatformFeeBatch channel message: {}",
                e
            );
        }

        Ok(())
    }

    /// Process BTC intent manager update batch after BTC batch is finalized
    /// This runs another round to select a final node that will:
    /// 1. Get intents with network_to_target_tx_id but not Solved
    /// 2. Create batch and broadcast via btc-intent-manager-tx-update
    /// 3. Make contract call to processBatchIntents to update tx-id on contract
    #[allow(dead_code)]
    pub(crate) async fn process_btc_intent_manager_update_batch_internal(
        btc_batch_round: u64,
        btc_txid: &str,
        message_tx: mpsc::Sender<ChannelMessage>,
        user_intent_manager: Option<Arc<UserIntentManager>>,
        coordination: &mut Coordination,
        node_id: String,
    ) -> Result<()> {
        info!(
            "🔄 [BTC_INTENT_MANAGER] Starting contract update batch process for BTC batch round {} (txid: {})",
            btc_batch_round, btc_txid
        );

        // Get user intent manager
        let user_intent_manager = user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        // Get database to access IntentStorage directly
        let database = user_intent_manager.get_database();
        let intent_storage = crate::database::storage::IntentStorage::new(database.clone());

        // Get intents with BOTH user_to_network_tx_id AND network_to_target_tx_id (completed intents)
        let completed_intents = intent_storage.get_completed_intents().await?;

        // Filter: must have BOTH TXIDs, BTC target chain, and status NOT Solved
        let mut eligible_intents = Vec::new();
        for (intent_hash, intent, tx_ids) in completed_intents {
            // Check if intent status is NOT Solved
            if let Some(user) = user_intent_manager
                .get_user_by_intent_hash(&intent_hash)
                .await
            {
                if let Some(status) = user.intent_hashes.get(&intent_hash) {
                    if *status == crate::types::IntentStatus::Solved {
                        continue; // Skip solved intents
                    }
                }
            }

            // Must be BTC target chain
            let target_chain_lower = intent.target_chain.to_lowercase();
            if target_chain_lower != "bitcoin" && target_chain_lower != "btc" {
                continue;
            }

            eligible_intents.push((intent_hash, intent, tx_ids));
        }

        if eligible_intents.is_empty() {
            info!(
                "ℹ️ [BTC_INTENT_MANAGER] No eligible intents found for contract update batch"
            );
            return Ok(());
        }

        info!(
            "📋 [BTC_INTENT_MANAGER] Found {} eligible intents for contract update batch",
            eligible_intents.len()
        );

        // Get available nodes
        let available_nodes: Vec<libp2p::PeerId> = coordination
            .get_available_nodes()
            .await;

        if available_nodes.is_empty() {
            warn!("⚠️ [BTC_INTENT_MANAGER] No available nodes for selection");
            return Ok(());
        }

        // Get next round in a block so we can release vrf_service borrow before replicate_vrf_round_to_consensus
        let update_round = {
            let vrf_service = coordination
                .vrf_service()
                .ok_or_else(|| anyhow!("Round/selection service not available"))?;
            if let Err(e) = vrf_service.sync_rounds_before_signing().await {
                warn!("⚠️ [BTC_INTENT_MANAGER] Failed to sync rounds: {}", e);
            }
            vrf_service.get_next_round().await
        };
        coordination.replicate_vrf_round_to_consensus(update_round);

        info!(
            "🎯 [BTC_INTENT_MANAGER] Performing selection for contract update batch (round {})",
            update_round
        );

        // Perform node selection
        let vrf_service = coordination
            .vrf_service()
            .ok_or_else(|| anyhow!("Round/selection service not available"))?;
        match vrf_service
            .perform_node_selection(
                &available_nodes,
                crate::vrf::VRF_NODE_SELECTION_COUNT,
                update_round,
                "btc_intent_manager_update",
            )
            .await
        {
            Ok(_selection_result) => {
                info!(
                    "✅ [BTC_INTENT_MANAGER] Selection completed for round {}",
                    update_round
                );
            }
            Err(e) => {
                error!("❌ [BTC_INTENT_MANAGER] Selection failed: {}", e);
                return Err(e);
            }
        }

        // Wait for consensus to complete and check if this node is the final node
        // The final node will handle the batch creation and contract call
        // For now, we'll create the batch message and broadcast it
        // The final node will be determined by consensus

        // Prepare intent hashes for the batch
        let intent_hashes: Vec<String> = eligible_intents
            .iter()
            .map(|(hash, _, _)| hash.clone())
            .collect();

        // Create batch timestamp
        let batch_timestamp = chrono::Utc::now().to_rfc3339();

        // NOTE: This static function doesn't have access to nonce_manager.
        // The nonce_tuple_id should be reserved by the caller and passed as a parameter.
        // For now, we set it to None and let the handler use the fallback path.
        // TODO: Update callers to pass nonce_tuple_id when this function is used.
        let nonce_tuple_id: Option<String> = None;

        // Broadcast via btc-intent-manager-tx-update topic
        let batch_message = crate::types::ChannelMessage::BtcIntentManagerTxUpdate {
            intent_hashes: intent_hashes.clone(),
            btc_txid: btc_txid.to_string(),
            btc_batch_round,
            update_round,
            timestamp: batch_timestamp,
            node_id: node_id.clone(),
            nonce_tuple_ids: nonce_tuple_id.map(|id| vec![id]),
        };

        message_tx
            .send(batch_message)
            .await
            .map_err(|e| anyhow!("Failed to send BTC intent manager update message: {}", e))?;

        info!(
            "✅ [BTC_INTENT_MANAGER] Broadcasted contract update batch with {} intents (BTC txid: {})",
            intent_hashes.len(),
            btc_txid
        );

        Ok(())
    }

    /// Get message/digest and transaction type for a round
    pub(crate) async fn get_message_and_type_for_round(
        &self,
        round: u64,
        slot_id: Option<&str>,
    ) -> Result<(Vec<u8>, Option<TransactionType>, Option<String>)> {
        // TICS UserToVault batch: slot_id is intent_hash; get tx from user_to_vault_tics_batch
        // BTC UserToVault batch: same slot_id; get tx from user_to_vault_btc_batch, digest = sighash
        if let Some(slot) = slot_id {
            let batch = self.pending.user_to_vault_tics_batch.read().await;
            if let Some(entries) = batch.get(&round) {
                if let Some((_intent_hash, user_eth, _chain_tx, tx_bytes)) =
                    entries.iter().find(|(h, ..)| h == slot)
                {
                    let mut hasher = sha3::Keccak256::new();
                    hasher.update(tx_bytes);
                    let digest = hasher.finalize().to_vec();
                    return Ok((
                        digest,
                        Some(TransactionType::UserToVault),
                        Some(user_eth.clone()),
                    ));
                }
            }
            let btc_batch = self.pending.user_to_vault_btc_batch.read().await;
            if let Some(entries) = btc_batch.get(&round) {
                if let Some((_intent_hash, user_eth, chain_tx, _, _)) =
                    entries.iter().find(|(h, ..)| h == slot)
                {
                    if let crate::chain_abstraction::ChainTransaction::Bitcoin(btc_tx) = chain_tx {
                        let inp0 = btc_tx
                            .inputs
                            .get(0)
                            .ok_or_else(|| anyhow!("BTC batch slot {} has no inputs", slot))?;
                        let prev_spk = inp0
                            .witness_utxo
                            .as_ref()
                            .ok_or_else(|| anyhow!("Input 0 missing witness_utxo for slot {}", slot))?
                            .script_pubkey
                            .clone();
                        let digest = self.compute_legacy_sighash_all_p2pkh(btc_tx, 0, &prev_spk)?;
                        return Ok((
                            digest.to_vec(),
                            Some(TransactionType::UserToVault),
                            Some(user_eth.clone()),
                        ));
                    }
                }
            }
            return Err(anyhow!(
                "No TICS or BTC UserToVault batch slot {} for round {}",
                slot,
                round
            ));
        }

        // Check if it's a claim-reward, claim-platform-fee, withdraw, or regular round
        let is_claim_reward_round = {
            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
            claim_reward_rounds.contains(&round)
        };
        let is_claim_platform_fee_round = {
            let r = self.pending.claim_platform_fee_rounds.read().await;
            r.contains(&round)
        };

        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };

        // Try TICS transactions first, then BTC
        //
        // NOTE: For partial signature verification we may override the stored transaction_type
        // for certain contract calls (e.g. IntentManager.processBatchIntents) so that verification
        // is performed against the VAULT/main key path.
        let (tx_bytes, transaction_type, user_tics_address, _chain_tx_opt) = if is_claim_reward_round {
            // Claim-reward: try TICS (contract) first, then BTC
            let claim_reward_pt_tics = self.pending.claim_reward_pending_transactions_tics.read().await;
            if let Some((chain_tx, tx_bytes, _identifiers, tx_type, _request_id, _original_request)) =
                claim_reward_pt_tics.get(&round)
            {
                (tx_bytes.clone(), tx_type.clone(), None, Some(chain_tx.clone()))
            } else {
                let claim_reward_pt_btc = self.pending.claim_reward_pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, _solver_address, tx_type, _extras)) =
                    claim_reward_pt_btc.get(&round)
                {
                    (tx_bytes.clone(), tx_type.clone(), None, None)
                } else {
                    return Err(anyhow!(
                        "No pending transaction found for claim-reward round {}",
                        round
                    ));
                }
            }
        } else if is_claim_platform_fee_round {
            // Claim-platform-fee: try TICS store first (contract call), then BTC store
            let claim_pf_pt_tics = self.pending.claim_platform_fee_pending_transactions_tics.read().await;
            if let Some((chain_tx, tx_bytes, _identifiers, tx_type, _request_id, _original_request)) =
                claim_pf_pt_tics.get(&round)
            {
                (tx_bytes.clone(), tx_type.clone(), None, Some(chain_tx.clone()))
            } else {
                drop(claim_pf_pt_tics);
                let claim_pf_pt_btc = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, _solver_address, tx_type, _extras)) =
                    claim_pf_pt_btc.get(&round)
                {
                    (tx_bytes.clone(), tx_type.clone(), None, None)
                } else {
                    return Err(anyhow!(
                        "No pending transaction found for claim-platform-fee round {}",
                        round
                    ));
                }
            }
        } else if is_withdraw_round {
            let withdraw_pt = self.pending.withdraw_pending_transactions_tics.read().await;
            if let Some((chain_tx, tx_bytes, _solver_address, tx_type, _request_id, _original_request)) =
                withdraw_pt.get(&round) {
                (tx_bytes.clone(), tx_type.clone(), None, Some(chain_tx.clone()))
            } else {
                // Try BTC withdraw
                let withdraw_pt_btc = self.pending.withdraw_pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, _solver_address, tx_type, _request_id)) =
                    withdraw_pt_btc.get(&round)
                {
                    (tx_bytes.clone(), tx_type.clone(), None, None)
                } else {
                    return Err(anyhow!(
                        "No pending transaction found for withdraw round {}",
                        round
                    ));
                }
            }
        } else {
            // Regular transaction - try TICS first
            let pending = self.pending.pending_transactions.read().await;
            if let Some((chain_tx, tx_bytes, intent_hash, tx_type, _request_id, _original_request)) = pending.get(&round) {
                // For UserToVault transactions, retrieve user_tics_address from intent_hash
                // This ensures the final node retrieves the address on its own, not relying on the unicasting peer
                let user_addr = if matches!(
                    tx_type,
                    Some(crate::types::TransactionType::UserToVault)
                ) {
                    if let Some(intent_hash) = intent_hash {
                        // Retrieve user's TICS address from intent hash using database
                        if let Some(database) = &self.database {
                            use crate::database::storage::UserStorage;
                            let user_storage = UserStorage::new(database.as_ref().clone());
                            match user_storage.get_user_by_intent_hash(intent_hash).await {
                                Ok(Some(user)) => {
                                    info!(
                                        "🔍 [SIGNING] Retrieved user_tics_address {} from intent_hash {} for UserToVault transaction (round {})",
                                        user.tics_address, intent_hash, round
                                    );
                                    Some(user.tics_address)
                                }
                                Ok(None) => {
                                    warn!(
                                        "⚠️ [SIGNING] No user found for intent_hash {} in UserToVault transaction (round {})",
                                        intent_hash, round
                                    );
                                    None
                                }
                                Err(e) => {
                                    warn!(
                                        "⚠️ [SIGNING] Failed to retrieve user from intent_hash {}: {} (round {})",
                                        intent_hash, e, round
                                    );
                                    None
                                }
                            }
                        } else {
                            warn!(
                                "⚠️ [SIGNING] Database not available to retrieve user_tics_address from intent_hash {} (round {})",
                                intent_hash, round
                            );
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                (tx_bytes.clone(), tx_type.clone(), user_addr, Some(chain_tx.clone()))
            } else {
                // Try BTC
                let pending_btc = self.pending.pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, intent_hashes, tx_type, _extras)) =
                    pending_btc.get(&round)
                {
                    // For UserToVault transactions, retrieve user_tics_address from intent_hash
                    // This ensures the final node retrieves the address on its own, not relying on the unicasting peer
                    let user_addr = if matches!(
                        tx_type,
                        Some(crate::types::TransactionType::UserToVault)
                    ) {
                        if let Some(intent_hashes_vec) = intent_hashes {
                            if let Some(first_intent_hash) = intent_hashes_vec.first() {
                                // Retrieve user's TICS address from intent hash using database
                                if let Some(database) = &self.database {
                                    use crate::database::storage::UserStorage;
                                    let user_storage = UserStorage::new(database.as_ref().clone());
                                    match user_storage.get_user_by_intent_hash(first_intent_hash).await {
                                        Ok(Some(user)) => {
                                            info!(
                                                "🔍 [SIGNING] Retrieved user_tics_address {} from intent_hash {} for UserToVault BTC transaction (round {})",
                                                user.tics_address, first_intent_hash, round
                                            );
                                            Some(user.tics_address)
                                        }
                                        Ok(None) => {
                                            warn!(
                                                "⚠️ [SIGNING] No user found for intent_hash {} in UserToVault BTC transaction (round {})",
                                                first_intent_hash, round
                                            );
                                            None
                                        }
                                        Err(e) => {
                                            warn!(
                                                "⚠️ [SIGNING] Failed to retrieve user from intent_hash {}: {} (round {})",
                                                first_intent_hash, e, round
                                            );
                                            None
                                        }
                                    }
                                } else {
                                    warn!(
                                        "⚠️ [SIGNING] Database not available to retrieve user_tics_address from intent_hash (round {})",
                                        round
                                    );
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    (tx_bytes.clone(), tx_type.clone(), user_addr, None)
                } else {
                    return Err(anyhow!("No pending transaction found for round {}", round));
                }
            }
        };

        // Retrieve intent hashes context for this round (single vs batch vs none)
        let intent_hashes_for_round = {
            let map = self.pending.intent_hashes_by_round.read().await;
            map.get(&round).cloned().unwrap_or_default()
        };

        if intent_hashes_for_round.len() > 1 {
            info!(
                "📦 [SIGNING] Round {} identified as BATCH transaction ({} intents)",
                round,
                intent_hashes_for_round.len()
            );
        } else if intent_hashes_for_round.len() == 1 {
            info!(
                "🧾 [SIGNING] Round {} identified as SINGLE transaction (intent: {})",
                round,
                intent_hashes_for_round[0]
            );
        } else {
            info!(
                "🧾 [SIGNING] Round {} has no intent hashes (solver-only or contract path)",
                round
            );
        }

        // NOTE: IntentManager.processBatchIntents contract txs are signed with the MAIN DKG key
        // (network group key path) and should therefore use the normal NetworkToTarget verification
        // path (network share pubkeys) for partial signature verification.

        // Hash the transaction bytes to get the digest
        let mut hasher = sha3::Keccak256::new();
        hasher.update(&tx_bytes);
        let digest = hasher.finalize().to_vec();
        
        info!(
            "🔍 [SIGNING] Computed digest for round {}: 0x{} (tx_bytes len: {}, tx_type: {:?})",
            round,
            hex::encode(&digest),
            tx_bytes.len(),
            transaction_type
        );
        
        // Log first and last bytes of tx_bytes for debugging digest mismatches
        if !tx_bytes.is_empty() {
            let first_bytes = if tx_bytes.len() >= 32 {
                hex::encode(&tx_bytes[0..32.min(tx_bytes.len())])
            } else {
                hex::encode(&tx_bytes)
            };
            let last_bytes = if tx_bytes.len() >= 32 {
                hex::encode(&tx_bytes[tx_bytes.len().saturating_sub(32)..])
            } else {
                hex::encode(&tx_bytes)
            };
            info!(
                "🔍 [SIGNING] Round {} tx_bytes preview: first 32 bytes: 0x{}, last 32 bytes: 0x{}",
                round, first_bytes, last_bytes
            );
        }

        Ok((digest, transaction_type, user_tics_address))
    }

}
