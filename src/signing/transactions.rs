use super::SigningNode;
use crate::{
    chain_abstraction::ChainTransaction,
    types::{intent::DepositIntent, ChannelMessage, TransactionNetwork, TransactionType},
};
use anyhow::{anyhow, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

impl SigningNode {
    pub(crate) async fn store_reward_transaction_btc(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        solver_address: String,
        extras: crate::signing::state::BtcRoundExtras,
    ) {
        let mut pending = self.pending.reward_pending_transactions_btc.write().await;
        pending.insert(
            round,
            (chain_tx, tx_bytes, Some(solver_address), Some(TransactionType::RewardTxn), Some(extras)),
        );
        info!(
            "🎁 [SIGNING] Stored BTC reward transaction for round {} with solver address",
            round
        );
    }

    pub(crate) async fn store_withdraw_transaction_tics(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        solver_address: String,
    ) {
        let mut pending = self
            .pending
            .withdraw_pending_transactions_tics
            .write()
            .await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                Some(solver_address),
                Some(TransactionType::WithdrawLiquidity),
            ),
        );
        info!(
            "💧 [SIGNING] Stored TICS withdraw-liquidity transaction for round {} with solver address",
            round
        );
    }

    pub(crate) async fn store_withdraw_transaction_btc(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        solver_address: String,
        extras: crate::signing::state::BtcRoundExtras,
    ) {
        let mut pending = self.pending.withdraw_pending_transactions_btc.write().await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                Some(solver_address),
                Some(TransactionType::WithdrawLiquidity),
                Some(extras),
            ),
        );
        info!(
            "💧 [SIGNING] Stored BTC withdraw-liquidity transaction for round {} with solver address",
            round
        );
    }

    pub(crate) async fn store_transaction_error_for_round(
        &self,
        round: u64,
        error_message: &str,
        txn_network: TransactionNetwork,
    ) {
        let is_reward_round = {
            let reward_rounds = self.pending.reward_rounds.read().await;
            reward_rounds.contains(&round)
        };

        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };

        let (intent_hash, transaction_type, retrieved_solver_address) = match txn_network {
            TransactionNetwork::TICS => {
                if is_reward_round {
                    let reward_pending_transactions =
                        self.pending.reward_pending_transactions_tics.read().await;
                    if let Some((_tx, _tx_bytes, solver_address, transaction_type)) =
                        reward_pending_transactions.get(&round)
                    {
                        (None, transaction_type.clone(), solver_address.clone())
                    } else {
                        (None, None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions =
                        self.pending.withdraw_pending_transactions_tics.read().await;
                    if let Some((_tx, _tx_bytes, solver_address, transaction_type)) =
                        withdraw_pending_transactions.get(&round)
                    {
                        (None, transaction_type.clone(), solver_address.clone())
                    } else {
                        (None, None, None)
                    }
                } else {
                    let pending = self.pending.pending_transactions.read().await;
                    if let Some((_tx, _tx_bytes, intent_hash, tx_type)) = pending.get(&round) {
                        (intent_hash.clone(), tx_type.clone(), None)
                    } else {
                        (None, None, None)
                    }
                }
            }
            TransactionNetwork::BTC => {
                if is_reward_round {
                    let reward_pending_transactions_btc =
                        self.pending.reward_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, solver_address, transaction_type, _extras)) =
                        reward_pending_transactions_btc.get(&round)
                    {
                        (None, transaction_type.clone(), solver_address.clone())
                    } else {
                        (None, None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions_btc =
                        self.pending.withdraw_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, solver_address, transaction_type, _extras)) =
                        withdraw_pending_transactions_btc.get(&round)
                    {
                        (None, transaction_type.clone(), solver_address.clone())
                    } else {
                        (None, None, None)
                    }
                } else {
                    let pending_btc = self.pending.pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, intent_hash, tx_type, _extras)) =
                        pending_btc.get(&round)
                    {
                        (intent_hash.clone(), tx_type.clone(), None)
                    } else {
                        (None, None, None)
                    }
                }
            }
        };

        // Reward transactions should never have an intent_hash
        // If transaction_type is RewardTxn but we have an intent_hash, log a warning
        if matches!(
            transaction_type,
            Some(crate::types::TransactionType::RewardTxn)
        ) && intent_hash.is_some()
        {
            warn!(
                "⚠️ [SIGNING] RewardTxn transaction type found with intent_hash (round={}); clearing intent hash path is expected",
                round
            );
        }

        match (intent_hash, &self.user_intent_manager) {
            (Some(ref intent_hash), Some(user_intent_manager)) => {
                // Handle reward transactions first (transaction_type is None but we have solver_address)
                // These should not have an intent_hash, but if they do, handle them here
                if transaction_type.is_none() && retrieved_solver_address.is_some() {
                    info!(
                        "💥 [SIGNING] Broadcasting reward transaction error for solver {:?} (round {}) - storage will be handled by message handler",
                        retrieved_solver_address, round
                    );

                    self.broadcast_transaction_error(
                        None,
                        error_message,
                        "reward_txn",
                        retrieved_solver_address.as_deref(),
                    )
                    .await;
                    return;
                }

                // For UserToVault, NetworkToTarget, and VaultToNetwork, store and broadcast
                let transaction_type_str = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => "user_to_vault",
                    Some(crate::types::TransactionType::NetworkToTarget) => {
                        "network_to_target"
                    }
                    Some(crate::types::TransactionType::VaultToNetwork) => {
                        "vault_to_network"
                    }
                    Some(crate::types::TransactionType::WithdrawLiquidity) => {
                        // Withdraw liquidity transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] WithdrawLiquidity transaction type found with intent_hash - this is invalid."
                        );
                        return;
                    }
                    Some(crate::types::TransactionType::AddLiquidity) => {
                        error!(
                            "❌ [SIGNING] AddLiquidity transaction type found with intent_hash - this flow is not supported."
                        );
                        return;
                    }
                    Some(crate::types::TransactionType::RewardTxn) => {
                        // Reward transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] RewardTxn transaction type found with intent_hash - this is invalid."
                        );
                        return;
                    }
                    None => {
                        // This shouldn't happen if we already handled reward transactions above
                        error!(
                            "❌ [SIGNING] Transaction type is None but no solver address available"
                        );
                        return;
                    }
                };

                match user_intent_manager
                    .store_transaction_error(intent_hash, error_message, None)
                    .await
                {
                    Ok(()) => {
                        info!(
                            "💥 [SIGNING] Stored transaction error for intent {} (round {}): {}",
                            intent_hash, round, error_message
                        );

                        self.broadcast_transaction_error(
                            Some(intent_hash),
                            error_message,
                            transaction_type_str,
                            None,
                        )
                        .await;

                        if matches!(
                            transaction_type,
                            Some(crate::types::TransactionType::NetworkToTarget)
                        ) {
                            info!(
                                "💸 [SIGNING] Network-to-target transaction failed, initiating refund for intent: {}",
                                intent_hash
                            );
                            if let Err(e) = self.initiate_refund_transaction(intent_hash).await {
                                error!("❌ [SIGNING] Failed to initiate refund transaction: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to store transaction error for intent {}: {}",
                            intent_hash, e
                        );
                    }
                }
            }
            (None, Some(_)) => {
                // Handle reward transactions (RewardTxn) - they should always have None for intent_hash
                // Also handle cases where transaction_type is None but we have a solver_address (legacy reward transactions)
                if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::RewardTxn)
                ) || (transaction_type.is_none() && retrieved_solver_address.is_some())
                {
                    if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                        info!(
                            "💥 [SIGNING] Reward transaction error for solver {} (round {}): {}",
                            solver_addr, round, error_message
                        );

                        self.broadcast_transaction_error(
                            None,
                            error_message,
                            "reward_txn",
                            Some(solver_addr),
                        )
                        .await;
                    } else if matches!(
                        transaction_type,
                        Some(crate::types::TransactionType::RewardTxn)
                    ) {
                        error!(
                            "❌ [SIGNING] RewardTxn transaction type requires solver_address, but none was found in round {}",
                            round
                        );
                    } else {
                        info!(
                            "ℹ️ [SIGNING] No solver address available for reward transaction error in round {}",
                            round
                        );
                    }
                } else if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::WithdrawLiquidity)
                ) {
                    // Handle withdraw liquidity transactions similar to rewards
                    if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                        info!(
                            "💥 [SIGNING] Withdraw liquidity transaction error for solver {} (round {}): {}",
                            solver_addr, round, error_message
                        );

                        self.broadcast_transaction_error(
                            None,
                            error_message,
                            "withdraw_liquidity",
                            Some(solver_addr),
                        )
                        .await;
                    } else {
                        warn!(
                            "⚠️ [SIGNING] WithdrawLiquidity transaction type requires solver_address, but none was found in round {}",
                            round
                        );
                    }
                }
            }
            (_, None) => {
                info!("ℹ️ [NETWORK] No user registry available, skipping transaction error storage");
            }
        }
    }

    pub(crate) async fn initiate_refund_transaction(&self, intent_hash: &str) -> Result<()> {
        info!(
            "🔄 [SIGNING-REFUND] Starting refund process for intent: {}",
            intent_hash
        );

        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User registry not available for refund"))?;

        let intent = user_intent_manager
            .get_intent(intent_hash)
            .await
            .ok_or_else(|| anyhow!("Intent not found: {}", intent_hash))?;

        // Calculate refund amount: if UserToVault transaction exists, include 5% extra
        let refund_amount = if let Some(tx_ids) = user_intent_manager
            .get_intent_transaction_ids(intent_hash)
            .await
        {
            if tx_ids.user_to_network_tx_id.is_some() {
                // UserToVault transaction exists, refund original amount + 5% extra
                let full_amount = intent.amount + (intent.amount / 20);
                info!(
                    "💰 [SIGNING-REFUND] UserToVault transaction found, refunding full amount: {} (original: {} + 5% extra: {})",
                    full_amount, intent.amount, intent.amount / 20
                );
                full_amount
            } else {
                // No UserToVault transaction, refund original amount
                info!(
                    "💰 [SIGNING-REFUND] No UserToVault transaction found, refunding original amount: {}",
                    intent.amount
                );
                intent.amount
            }
        } else {
            // Couldn't check transaction IDs, refund original amount
            warn!(
                "⚠️ [SIGNING-REFUND] Could not check transaction IDs, refunding original amount: {}",
                intent.amount
            );
            intent.amount
        };

        info!(
            "📋 [SIGNING-REFUND] Found intent - Original Amount: {}, Refund Amount: {}, Source: {} ({}), Target: {} ({})",
            intent.amount,
            refund_amount,
            intent.source_address,
            intent.source_chain,
            intent.target_address,
            intent.target_chain
        );

        if let Err(e) = self.broadcast_refund_initiation(intent_hash, &intent, refund_amount).await {
            warn!(
                "⚠️ [SIGNING-REFUND] Failed to broadcast refund initiation: {}",
                e
            );
        }

        Ok(())
    }

    /// Check if a round is a NetworkToTarget transaction and trigger refund if signature verification fails
    pub(crate) async fn check_and_trigger_refund_on_verification_failure(
        &self,
        round: u64,
        txn_network: TransactionNetwork,
    ) {
        let (intent_hash, transaction_type) = match txn_network {
            TransactionNetwork::TICS => {
                let pending = self.pending.pending_transactions.read().await;
                if let Some((_tx, _tx_bytes, intent_hash, tx_type)) = pending.get(&round) {
                    (intent_hash.clone(), tx_type.clone())
                } else {
                    (None, None)
                }
            }
            TransactionNetwork::BTC => {
                let pending_btc = self.pending.pending_transactions_btc.read().await;
                if let Some((_tx, _tx_bytes, intent_hash, tx_type, _extras)) =
                    pending_btc.get(&round)
                {
                    (intent_hash.clone(), tx_type.clone())
                } else {
                    (None, None)
                }
            }
        };

        // Only trigger refund for NetworkToTarget transactions with an intent_hash
        if let (Some(ref intent_hash), Some(TransactionType::NetworkToTarget)) =
            (intent_hash, transaction_type)
        {
            info!(
                "💸 [SIGNING-REFUND] Signature verification failed for NetworkToTarget transaction, initiating refund for intent: {}",
                intent_hash
            );
            if let Err(e) = self.initiate_refund_transaction(intent_hash).await {
                error!("❌ [SIGNING-REFUND] Failed to initiate refund transaction: {}", e);
            }
        }
    }

    async fn broadcast_refund_initiation(
        &self,
        intent_hash: &str,
        intent: &DepositIntent,
        refund_amount: u128,
    ) -> Result<()> {
        let refund_msg = serde_json::json!({
            "type": "refund_initiation",
            "intent_hash": intent_hash,
            "source_address": intent.source_address,
            "source_chain": intent.source_chain,
            "original_amount": intent.amount.to_string(),
            "refund_amount": refund_amount.to_string(),
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        });

        let msg_bytes = serde_json::to_vec(&refund_msg)?;
        let channel_msg = ChannelMessage::RefundInitiation {
            intent_hash: intent_hash.to_string(),
            data: msg_bytes,
        };

        self.message_tx
            .send(channel_msg)
            .await
            .map_err(|e| anyhow!("Failed to broadcast refund initiation: {}", e))?;

        info!(
            "📢 [SIGNING-REFUND] Broadcasted refund initiation for intent: {}",
            intent_hash
        );
        Ok(())
    }

    pub(crate) async fn store_transaction_id_for_round(
        &mut self,
        round: u64,
        tx_id: &str,
        txn_network: TransactionNetwork,
    ) {
        info!(
            "💾 [SIGNING] Storing transaction ID for round {} (tx_id={}, txn_network={:?})",
            round, tx_id, txn_network
        );
        let is_reward_round = {
            let reward_rounds = self.pending.reward_rounds.read().await;
            reward_rounds.contains(&round)
        };
        info!("💾 [SIGNING] Is reward round: {}", is_reward_round);
        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };
        info!("💾 [SIGNING] Is withdraw round: {}", is_withdraw_round);

        let (intent_hash, transaction_type, retrieved_solver_address) = match txn_network {
            TransactionNetwork::TICS => {
                if is_reward_round {
                    let reward_pending_transactions =
                        self.pending.reward_pending_transactions_tics.read().await;
                    if let Some((_tx, _tx_bytes, solver_address, transaction_type)) =
                        reward_pending_transactions.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [TICS][Reward] Found reward_pending_transactions_tics entry for round {}: solver_address={:?}, transaction_type={:?}", round, solver_address, transaction_type);
                        (None, transaction_type.clone(), solver_address.clone())
                    } else {
                        warn!("[store_transaction_id_for_round] [TICS][Reward] No entry in reward_pending_transactions_tics for round {}", round);
                        (None, None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions =
                        self.pending.withdraw_pending_transactions_tics.read().await;
                    if let Some((_tx, _tx_bytes, solver_address, transaction_type)) =
                        withdraw_pending_transactions.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [TICS][Withdraw] Found withdraw_pending_transactions_tics entry for round {}: solver_address={:?}, transaction_type={:?}", round, solver_address, transaction_type);
                        (None, transaction_type.clone(), solver_address.clone())
                    } else {
                        warn!("[store_transaction_id_for_round] [TICS][Withdraw] No entry in withdraw_pending_transactions_tics for round {}", round);
                        (None, None, None)
                    }
                } else {
                    let pending_transactions = self.pending.pending_transactions.read().await;
                    if let Some((_tx, _tx_bytes, intent_hash, transaction_type)) =
                        pending_transactions.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [TICS][Non-Reward] Found pending_transactions entry for round {}: intent_hash={:?}, transaction_type={:?}", round, intent_hash, transaction_type);
                        (intent_hash.clone(), transaction_type.clone(), None)
                    } else {
                        warn!("[store_transaction_id_for_round] [TICS][Non-Reward] No entry in pending_transactions for round {}", round);
                        (None, None, None)
                    }
                }
            }
            TransactionNetwork::BTC => {
                if is_reward_round {
                    let reward_pending_transactions_btc =
                        self.pending.reward_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, solver_address, transaction_type, _extras)) =
                        reward_pending_transactions_btc.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [BTC][Reward] Found reward_pending_transactions_btc entry for round {}: solver_address={:?}, transaction_type={:?}", round, solver_address, transaction_type);
                        (None, transaction_type.clone(), solver_address.clone())
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][Reward] No entry in reward_pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions_btc =
                        self.pending.withdraw_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, solver_address, transaction_type, _extras)) =
                        withdraw_pending_transactions_btc.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [BTC][Withdraw] Found withdraw_pending_transactions_btc entry for round {}: solver_address={:?}, transaction_type={:?}", round, solver_address, transaction_type);
                        (None, transaction_type.clone(), solver_address.clone())
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][Withdraw] No entry in withdraw_pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                } else {
                    let pending_transactions_btc =
                        self.pending.pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, intent_hash, transaction_type, _extras)) =
                        pending_transactions_btc.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [BTC][Non-Reward] Found pending_transactions_btc entry for round {}: intent_hash={:?}, transaction_type={:?}", round, intent_hash, transaction_type);
                        (intent_hash.clone(), transaction_type.clone(), None)
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][Non-Reward] No entry in pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                }
            }
        };

        // Reward transactions should never have an intent_hash
        // If transaction_type is RewardTxn but we have an intent_hash, log a warning
        if matches!(
            transaction_type,
            Some(crate::types::TransactionType::RewardTxn)
        ) && intent_hash.is_some()
        {
            warn!(
                "⚠️ [SIGNING] RewardTxn transaction type found with intent_hash (round={}, tx_id={}); clearing intent hash path is expected",
                round,
                tx_id
            );
        }

        match (intent_hash, &self.user_intent_manager) {
            (Some(ref intent_hash), Some(_user_intent_manager)) => {
                // Handle reward transactions first (transaction_type is None but we have solver_address)
                // These should not have an intent_hash, but if they do, handle them here
                // Don't store transaction ID here - let handle_reward_transaction_id_storage handle it after broadcast
                if transaction_type.is_none() && retrieved_solver_address.is_some() {
                    info!(
                        "📡 [SIGNING] Broadcasting reward transaction ID {} for solver {:?} (round {}) - storage will be handled by message handler",
                        tx_id, retrieved_solver_address, round
                    );

                    self.broadcast_transaction_id(
                        None,
                        tx_id,
                        "reward_txn",
                        retrieved_solver_address.as_deref(),
                    )
                    .await;
                    return;
                }

                // For UserToVault, NetworkToTarget, and VaultToNetwork, just broadcast without storing
                // Storage will be handled by handle_transaction_id_storage when the broadcast message is received
                let transaction_type_str = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => {
                        if let Some(user_intent_manager) = &self.user_intent_manager {
                            if let Err(e) = user_intent_manager
                                .store_final_solver(intent_hash, self.id.as_str())
                                .await
                            {
                                warn!(
                                    "⚠️ [SIGNING] Failed to store final solver locally for intent {}: {}",
                                    intent_hash, e
                                );
                            }
                        }

                        info!(
                            "📡 [SIGNING] Broadcasting user-to-network transaction ID {} for intent {} (round {}) - storage will be handled by message handler",
                            tx_id, intent_hash, round
                        );
                        "user_to_vault"
                    }
                    Some(crate::types::TransactionType::NetworkToTarget) => {
                        info!(
                            "📡 [SIGNING] Broadcasting network-to-target transaction ID {} for intent {} (round {}) - storage will be handled by message handler",
                            tx_id, intent_hash, round
                        );
                        "network_to_target"
                    }
                    Some(crate::types::TransactionType::VaultToNetwork) => {
                        if let Some(user_intent_manager) = &self.user_intent_manager {
                            if let Err(e) = user_intent_manager
                                .store_final_solver(intent_hash, self.id.as_str())
                                .await
                            {
                                warn!(
                                    "⚠️ [SIGNING] Failed to store final solver locally for intent {}: {}",
                                    intent_hash, e
                                );
                            }
                        }

                        info!(
                            "📡 [SIGNING] Broadcasting vault-to-network transaction ID {} for intent {} (round {}) - storage will be handled by message handler",
                            tx_id, intent_hash, round
                        );
                        "vault_to_network"
                    }
                    Some(crate::types::TransactionType::WithdrawLiquidity) => {
                        // Withdraw liquidity transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] WithdrawLiquidity transaction type found with intent_hash - this is invalid."
                        );
                        return;
                    }
                    Some(crate::types::TransactionType::AddLiquidity) => {
                        error!(
                            "❌ [SIGNING] AddLiquidity transaction type found with intent_hash - this flow is not supported."
                        );
                        return;
                    }
                    Some(crate::types::TransactionType::RewardTxn) => {
                        // Reward transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] RewardTxn transaction type found with intent_hash - this is invalid."
                        );
                        return;
                    }
                    None => {
                        // This shouldn't happen if we already handled reward transactions above
                        error!(
                            "❌ [SIGNING] Transaction type is None but no solver address available"
                        );
                        return;
                    }
                };

                // Broadcast transaction ID for UserToVault, NetworkToTarget, or VaultToNetwork
                info!(
                    "📡 [SIGNING] Broadcasting transaction ID {} for intent {} (type: {})",
                    tx_id, intent_hash, transaction_type_str
                );

                self.broadcast_transaction_id(Some(intent_hash), tx_id, transaction_type_str, None)
                    .await;
            }
            (None, Some(_)) => {
                // Handle reward transactions (RewardTxn) - they should always have None for intent_hash
                // Also handle cases where transaction_type is None but we have a solver_address (legacy reward transactions)
                // Don't store transaction ID here - let handle_reward_transaction_id_storage handle it after broadcast
                if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::RewardTxn)
                ) || (transaction_type.is_none() && retrieved_solver_address.is_some())
                {
                    info!(
                        "🧾 [SIGNING] Reward path (round {}, network {:?}) solver_address_present={} tx_id={}",
                        round,
                        txn_network,
                        retrieved_solver_address.is_some(),
                        tx_id
                    );
                    if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                        info!(
                            "📡 [SIGNING] Broadcasting reward transaction ID {} for solver {} (round {}) - storage will be handled by message handler",
                            tx_id, solver_addr, round
                        );

                        self.broadcast_transaction_id(None, tx_id, "reward_txn", Some(solver_addr))
                            .await;
                    } else if matches!(
                        transaction_type,
                        Some(crate::types::TransactionType::RewardTxn)
                    ) {
                        error!(
                            "❌ [SIGNING] RewardTxn transaction type requires solver_address, but none was found in round {} (tx_id={})",
                            round,
                            tx_id
                        );
                    } else {
                        info!(
                            "ℹ️ [SIGNING] No solver address available for reward transaction in round {}",
                            round
                        );
                    }
                } else if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::WithdrawLiquidity)
                ) {
                    // Handle withdraw liquidity transactions similar to rewards
                    // Don't store transaction ID here - let handle_withdraw_liquidity_transaction_id_storage handle it after broadcast
                    if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                        info!(
                            "📡 [SIGNING] Broadcasting withdraw liquidity transaction ID {} for solver {} (round {}) - storage will be handled by message handler",
                            tx_id, solver_addr, round
                        );

                        self.broadcast_transaction_id(
                            None,
                            tx_id,
                            "withdraw_liquidity",
                            Some(solver_addr),
                        )
                        .await;
                    } else {
                        warn!(
                            "⚠️ [SIGNING] WithdrawLiquidity transaction type requires solver_address, but none was found in round {} (tx_id={})",
                            round, tx_id
                        );
                    }
                }
            }
            (_, None) => {
                info!("ℹ️ [NETWORK] No user registry available, skipping transaction ID storage");
            }
        }
    }

    pub(crate) async fn broadcast_transaction_id(
        &self,
        intent_hash: Option<&str>,
        tx_id: &str,
        transaction_type: &str,
        solver_address: Option<&str>,
    ) {
        let channel_message_transaction_id_broadcast =
            crate::types::ChannelMessage::TransactionIdBroadcast {
                intent_hash: intent_hash.map(|s| s.to_string()),
                transaction_id: tx_id.to_string(),
                transaction_type: transaction_type.to_string(),
                solver_address: solver_address.map(|s| s.to_string()),
                node_id: self.id.clone(),
            };

        if let Err(e) = self
            .message_tx
            .send(channel_message_transaction_id_broadcast)
            .await
        {
            error!(
                "❌ [SIGNING] Failed to broadcast transaction ID to other nodes: {}",
                e
            );
        } else {
            match (intent_hash, solver_address) {
                (Some(hash), _) => {
                    info!(
                        "📡 [SIGNING] Broadcasted transaction ID {} for intent {} (type: {}) to other nodes",
                        tx_id, hash, transaction_type
                    );
                }
                (None, Some(solver)) => {
                    info!(
                        "📡 [SIGNING] Broadcasted reward transaction ID {} for solver {} (type: {}) to other nodes",
                        tx_id, solver, transaction_type
                    );
                }
                (None, None) => {
                    warn!(
                        "⚠️ [SIGNING] Broadcasted transaction ID {} without intent hash or solver address (type: {})",
                        tx_id, transaction_type
                    );
                }
            }
        }
    }

    pub(crate) async fn broadcast_transaction_error(
        &self,
        intent_hash: Option<&str>,
        error_message: &str,
        transaction_type: &str,
        solver_address: Option<&str>,
    ) {
        let broadcast_message = crate::types::GossipsubMessage::TransactionErrorBroadcast {
            intent_hash: intent_hash.map(|s| s.to_string()),
            error_message: error_message.to_string(),
            transaction_type: transaction_type.to_string(),
            solver_address: solver_address.map(|s| s.to_string()),
            node_id: self.id.clone(),
        };

        let channel_message = crate::types::ChannelMessage::Broadcast {
            topic: "transaction-error-sync".to_string(),
            data: serde_json::to_vec(&broadcast_message).unwrap_or_default(),
        };

        if let Err(e) = self.message_tx.send(channel_message).await {
            error!(
                "❌ [SIGNING] Failed to broadcast transaction error to other nodes: {}",
                e
            );
        } else {
            match (intent_hash, solver_address) {
                (Some(hash), _) => {
                    info!(
                        "📡 [SIGNING] Broadcasted transaction error for intent {} (type: {}) to other nodes: {}",
                        hash, transaction_type, error_message
                    );
                }
                (None, Some(solver)) => {
                    info!(
                        "📡 [SIGNING] Broadcasted reward transaction error for solver {} (type: {}) to other nodes: {}",
                        solver, transaction_type, error_message
                    );
                }
                (None, None) => {
                    warn!(
                        "⚠️ [SIGNING] Broadcasted transaction error without intent hash or solver address (type: {}): {}",
                        transaction_type, error_message
                    );
                }
            }
        }
    }
}
