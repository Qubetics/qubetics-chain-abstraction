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
            (
                chain_tx,
                tx_bytes,
                Some(vec![solver_address]),
                Some(TransactionType::RewardTxn),
                Some(extras),
            ),
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
                Some(vec![solver_address]),
                Some(TransactionType::WithdrawLiquidity),
                None,
                None,
            ),
        );
        info!(
            "💧 [SIGNING] Stored TICS withdraw-liquidity transaction for round {} with solver address",
            round
        );
    }

    /// Store TICS withdraw batch (one EVM tx-id for multiple requests). identifiers are "request_id|solver_address".
    pub(crate) async fn store_withdraw_transaction_tics_batch(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
    ) {
        if identifiers.is_empty() {
            return;
        }
        let mut pending = self
            .pending
            .withdraw_pending_transactions_tics
            .write()
            .await;
        let count = identifiers.len();
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                Some(identifiers),
                Some(TransactionType::WithdrawLiquidity),
                None,
                None,
            ),
        );
        let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
        withdraw_rounds.insert(round);
        info!(
            "💧 [SIGNING] Stored TICS withdraw-liquidity batch for round {} with {} request(s)",
            round, count
        );
    }

    pub(crate) async fn store_withdraw_transaction_btc(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
        extras: crate::signing::state::BtcRoundExtras,
    ) {
        // For BTC withdraws we repurpose the "intent_hashes" slot in PendingValue
        // to carry the batch context: each entry is encoded as "request_id|solver_address".
        let mut pending = self.pending.withdraw_pending_transactions_btc.write().await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                if identifiers.is_empty() {
                    None
                } else {
                    Some(identifiers)
                },
                Some(TransactionType::WithdrawLiquidity),
                Some(extras),
            ),
        );
        info!(
            "💧 [SIGNING] Stored BTC withdraw-liquidity transaction for round {} with batch metadata",
            round
        );
    }

    pub(crate) async fn store_claim_reward_transaction_btc(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
        extras: crate::signing::state::BtcRoundExtras,
    ) {
        let mut pending = self.pending.claim_reward_pending_transactions_btc.write().await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                if identifiers.is_empty() {
                    None
                } else {
                    Some(identifiers)
                },
                Some(TransactionType::ClaimRewardBtc),
                Some(extras),
            ),
        );
        {
            let mut rounds = self.pending.claim_reward_rounds.write().await;
            rounds.insert(round);
        }
        info!(
            "🎁 [SIGNING] Stored BTC claim-reward transaction for round {} with batch metadata",
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

        let (intent_hashes, transaction_type, retrieved_solver_address) = match txn_network {
            TransactionNetwork::TICS => {
                if is_reward_round {
                    let reward_pending_transactions =
                        self.pending.reward_pending_transactions_tics.read().await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        solver_address,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = reward_pending_transactions.get(&round)
                    {
                        (vec![], transaction_type.clone(), solver_address.clone())
                    } else {
                        (vec![], None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions =
                        self.pending.withdraw_pending_transactions_tics.read().await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        identifiers,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = withdraw_pending_transactions.get(&round)
                    {
                        let solver_address = identifiers.as_ref().and_then(|v| v.first()).map(|s| {
                            if let Some((_, solver)) = s.split_once('|') {
                                solver.to_string()
                            } else {
                                s.clone()
                            }
                        });
                        (vec![], transaction_type.clone(), solver_address)
                    } else {
                        (vec![], None, None)
                    }
                } else {
                    let (from_pending, tx_type) = {
                        let pending = self.pending.pending_transactions.read().await;
                        pending
                            .get(&round)
                            .map(|(_, _, h, t, _, _)| (h.clone(), t.clone()))
                            .unwrap_or((None, None))
                    };
                    let list = {
                        let map = self.pending.intent_hashes_by_round.read().await;
                        map.get(&round)
                            .cloned()
                            .unwrap_or_else(|| from_pending.map(|h| vec![h]).unwrap_or_default())
                    };
                    (list, tx_type, None)
                }
            }
            TransactionNetwork::BTC => {
                if is_reward_round {
                    let reward_pending_transactions_btc =
                        self.pending.reward_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, solver_addresses, transaction_type, _extras)) =
                        reward_pending_transactions_btc.get(&round)
                    {
                        let solver_address =
                            solver_addresses.as_ref().and_then(|v| v.first().cloned());
                        (vec![], transaction_type.clone(), solver_address)
                    } else {
                        (vec![], None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions_btc =
                        self.pending.withdraw_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, solver_addresses, transaction_type, _extras)) =
                        withdraw_pending_transactions_btc.get(&round)
                    {
                        let solver_address =
                            solver_addresses.as_ref().and_then(|v| v.first().cloned());
                        (vec![], transaction_type.clone(), solver_address)
                    } else {
                        (vec![], None, None)
                    }
                } else {
                    let from_pending = {
                        let pending_btc = self.pending.pending_transactions_btc.read().await;
                        pending_btc
                            .get(&round)
                            .and_then(|(_, _, h, _, _)| h.clone())
                            .unwrap_or_default()
                    };
                    let list = {
                        let map = self.pending.intent_hashes_by_round.read().await;
                        map.get(&round)
                            .cloned()
                            .unwrap_or_else(|| from_pending)
                    };
                    let tx_type = {
                        let pending_btc = self.pending.pending_transactions_btc.read().await;
                        pending_btc
                            .get(&round)
                            .and_then(|(_, _, _, t, _)| t.clone())
                    };
                    (list, tx_type, None)
                }
            }
        };

        if !intent_hashes.is_empty()
            && matches!(
                transaction_type,
                Some(crate::types::TransactionType::RewardTxn)
            )
        {
            warn!(
                "⚠️ [SIGNING] RewardTxn with intent_hashes (round {}); clearing intent path",
                round
            );
        }

        // Intent-based batch: store, refund, and broadcast for all intents (batch-aware, like tx-id)
        if !intent_hashes.is_empty() {
            if let Some(user_intent_manager) = &self.user_intent_manager {
                let transaction_type_str = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => "user_to_vault",
                    Some(crate::types::TransactionType::NetworkToTarget) => "network_to_target",
                    Some(crate::types::TransactionType::Refund) => "refund",
                    Some(crate::types::TransactionType::IntentStatusUpdate) => "intent_status_update",
                    Some(crate::types::TransactionType::WithdrawLiquidity) => {
                        error!("❌ [SIGNING] WithdrawLiquidity with intent_hashes - invalid");
                        return;
                    }
                    Some(crate::types::TransactionType::RewardTxn) => {
                        error!("❌ [SIGNING] RewardTxn with intent_hashes - invalid");
                        return;
                    }
                    Some(crate::types::TransactionType::ClaimRewardBtc) => {
                        error!("❌ [SIGNING] ClaimRewardBtc with intent_hashes - invalid");
                        return;
                    }
                    None => {
                        // Check if this is an add_liquidity request (request_id starts with "addliq:")
                        if intent_hashes.iter().any(|h| h.starts_with("addliq:")) {
                            "add_liquidity"
                        } else {
                            error!("❌ [SIGNING] Transaction type is None for intent batch and not add_liquidity");
                            return;
                        }
                    }
                };

                for intent_hash in &intent_hashes {
                    if let Err(e) = user_intent_manager
                        .store_transaction_error(intent_hash, error_message, None)
                        .await
                    {
                        error!(
                            "❌ [SIGNING] Failed to store transaction error for intent {}: {}",
                            intent_hash, e
                        );
                    } else {
                        info!(
                            "💥 [SIGNING] Stored transaction error for intent {} (round {}): {}",
                            intent_hash, round, error_message
                        );
                    }

                    if matches!(
                        transaction_type,
                        Some(crate::types::TransactionType::NetworkToTarget)
                    ) {
                        info!(
                            "💸 [SIGNING] Network-to-target failed, initiating refund for intent: {}",
                            intent_hash
                        );
                        if let Err(e) = self.initiate_refund_transaction(intent_hash).await {
                            error!("❌ [SIGNING] Failed to initiate refund for {}: {}", intent_hash, e);
                        }
                    }
                }

                self.broadcast_transaction_error(
                    Some(intent_hashes.clone()),
                    error_message,
                    transaction_type_str,
                    None,
                )
                .await;
            }
            return;
        }

        // Reward / withdraw: no intent_hashes, use solver_address
        match (&retrieved_solver_address, &self.user_intent_manager) {
            (Some(_), _) | (_, Some(_)) => {}
            (None, None) => {
                info!(
                    "ℹ️ [NETWORK] No user registry available, skipping transaction error storage"
                );
                return;
            }
        }

        match (&retrieved_solver_address, &self.user_intent_manager) {
            (Some(_), _) | (_, Some(_)) => {
                if transaction_type.is_none() && retrieved_solver_address.is_some() {
                    info!(
                        "💥 [SIGNING] Broadcasting reward transaction error for solver {:?} (round {})",
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
                            Some(solver_addr.as_str()),
                        )
                        .await;
                    } else if matches!(
                        transaction_type,
                        Some(crate::types::TransactionType::RewardTxn)
                    ) {
                        error!(
                            "❌ [SIGNING] RewardTxn requires solver_address in round {}",
                            round
                        );
                    }
                } else if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::WithdrawLiquidity)
                ) {
                    if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                        info!(
                            "💥 [SIGNING] Withdraw liquidity transaction error for solver {} (round {}): {}",
                            solver_addr, round, error_message
                        );
                        self.broadcast_transaction_error(
                            None,
                            error_message,
                            "withdraw_liquidity",
                            Some(solver_addr.as_str()),
                        )
                        .await;
                    } else {
                        warn!(
                            "⚠️ [SIGNING] WithdrawLiquidity requires solver_address in round {}",
                            round
                        );
                    }
                }
            }
            (_, None) => {
                info!(
                    "ℹ️ [NETWORK] No user registry available, skipping transaction error storage"
                );
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

        // Parse intent amount from string
        let intent_amount = intent.amount.parse::<u128>().unwrap_or(0);

        // Calculate refund amount: if UserToVault transaction exists, include 5% extra
        let refund_amount = if let Some(tx_ids) = user_intent_manager
            .get_intent_transaction_ids(intent_hash)
            .await
        {
            if tx_ids.user_to_network_tx_id.is_some() {
                // UserToVault transaction exists, refund original amount + 5% extra
                let full_amount = intent_amount + (intent_amount / 20);
                info!(
                    "💰 [SIGNING-REFUND] UserToVault transaction found, refunding full amount: {} (original: {} + 5% extra: {})",
                    full_amount, intent_amount, intent_amount / 20
                );
                full_amount
            } else {
                // No UserToVault transaction, refund original amount
                info!(
                    "💰 [SIGNING-REFUND] No UserToVault transaction found, refunding original amount: {}",
                    intent_amount
                );
                intent_amount
            }
        } else {
            // Couldn't check transaction IDs, refund original amount
            warn!(
                "⚠️ [SIGNING-REFUND] Could not check transaction IDs, refunding original amount: {}",
                intent_amount
            );
            intent_amount
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

        if let Err(e) = self
            .broadcast_refund_initiation(intent_hash, &intent, refund_amount)
            .await
        {
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
                if let Some((
                    _tx,
                    _tx_bytes,
                    intent_hash,
                    tx_type,
                    _request_id,
                    _original_request,
                )) = pending.get(&round)
                {
                    (intent_hash.clone(), tx_type.clone())
                } else {
                    (None, None)
                }
            }
            TransactionNetwork::BTC => {
                let pending_btc = self.pending.pending_transactions_btc.read().await;
                if let Some((_tx, _tx_bytes, intent_hashes, tx_type, _extras)) =
                    pending_btc.get(&round)
                {
                    let intent_hash = intent_hashes.as_ref().and_then(|v| v.first().cloned());
                    (intent_hash, tx_type.clone())
                } else {
                    (None, None)
                }
            }
        };

        // Only trigger refund for NetworkToTarget transactions with an intent_hash
        if let (Some(intent_hash), Some(TransactionType::NetworkToTarget)) =
            (intent_hash.as_ref(), transaction_type.as_ref())
        {
            info!(
                "💸 [SIGNING-REFUND] Signature verification failed for NetworkToTarget transaction, initiating refund for intent: {}",
                intent_hash
            );
            if let Err(e) = self.initiate_refund_transaction(intent_hash).await {
                error!(
                    "❌ [SIGNING-REFUND] Failed to initiate refund transaction: {}",
                    e
                );
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
        let is_claim_reward_round = {
            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
            claim_reward_rounds.contains(&round)
        };
        info!("💾 [SIGNING] Is claim reward round: {}", is_claim_reward_round);

        let (intent_hash, transaction_type, retrieved_solver_address) = match txn_network {
            TransactionNetwork::TICS => {
                if is_reward_round {
                    let reward_pending_transactions =
                        self.pending.reward_pending_transactions_tics.read().await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        solver_address,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = reward_pending_transactions.get(&round)
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
                    if let Some((
                        _tx,
                        _tx_bytes,
                        identifiers,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = withdraw_pending_transactions.get(&round)
                    {
                        let solver_address = identifiers.as_ref().and_then(|v| v.first()).map(|s| {
                            if let Some((_, solver)) = s.split_once('|') {
                                solver.to_string()
                            } else {
                                s.clone()
                            }
                        });
                        info!("[store_transaction_id_for_round] [TICS][Withdraw] Found withdraw_pending_transactions_tics entry for round {}: identifiers={}, transaction_type={:?}", round, identifiers.as_ref().map(|v| v.len()).unwrap_or(0), transaction_type);
                        (None, transaction_type.clone(), solver_address)
                    } else {
                        warn!("[store_transaction_id_for_round] [TICS][Withdraw] No entry in withdraw_pending_transactions_tics for round {}", round);
                        (None, None, None)
                    }
                } else {
                    let pending_transactions = self.pending.pending_transactions.read().await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        intent_hash,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = pending_transactions.get(&round)
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
                    if let Some((_tx, _tx_bytes, solver_addresses, transaction_type, _extras)) =
                        reward_pending_transactions_btc.get(&round)
                    {
                        let solver_address =
                            solver_addresses.as_ref().and_then(|v| v.first().cloned());
                        info!("[store_transaction_id_for_round] [BTC][Reward] Found reward_pending_transactions_btc entry for round {}: solver_address={:?}, transaction_type={:?}", round, solver_address, transaction_type);
                        (None, transaction_type.clone(), solver_address)
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][Reward] No entry in reward_pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions_btc =
                        self.pending.withdraw_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, identifiers, transaction_type, _extras)) =
                        withdraw_pending_transactions_btc.get(&round)
                    {
                        // For BTC withdraws, the "intent_hashes" slot is repurposed to carry
                        // batch metadata encoded as "request_id|solver_address".
                        let solver_address = identifiers.as_ref().and_then(|v| {
                            v.iter().find_map(|encoded| {
                                encoded
                                    .split_once('|')
                                    .map(|(_, solver)| solver.to_string())
                            })
                        });
                        info!("[store_transaction_id_for_round] [BTC][Withdraw] Found withdraw_pending_transactions_btc entry for round {}: solver_address={:?}, transaction_type={:?}", round, solver_address, transaction_type);
                        (None, transaction_type.clone(), solver_address)
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][Withdraw] No entry in withdraw_pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                } else if is_claim_reward_round {
                    let claim_reward_pending_btc =
                        self.pending.claim_reward_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, identifiers, transaction_type, _extras)) =
                        claim_reward_pending_btc.get(&round)
                    {
                        let solver_address = identifiers.as_ref().and_then(|v| {
                            v.iter().find_map(|encoded| {
                                encoded
                                    .split_once('|')
                                    .map(|(_, solver)| solver.to_string())
                            })
                        });
                        info!("[store_transaction_id_for_round] [BTC][ClaimReward] Found claim_reward_pending_transactions_btc entry for round {}: transaction_type={:?}", round, transaction_type);
                        (None, transaction_type.clone(), solver_address)
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][ClaimReward] No entry in claim_reward_pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                } else {
                    let pending_transactions_btc =
                        self.pending.pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, intent_hashes, transaction_type, _extras)) =
                        pending_transactions_btc.get(&round)
                    {
                        let intent_hash = intent_hashes.as_ref().and_then(|v| v.first().cloned());
                        info!("[store_transaction_id_for_round] [BTC][Non-Reward] Found pending_transactions_btc entry for round {}: intent_hash={:?}, transaction_type={:?}", round, intent_hash, transaction_type);
                        (intent_hash, transaction_type.clone(), None)
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
                        vec![],
                        tx_id,
                        "reward_txn",
                        retrieved_solver_address.as_deref(),
                    )
                    .await;
                    return;
                }

                // For UserToVault, NetworkToTarget, and Refund, just broadcast without storing
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
                    Some(crate::types::TransactionType::IntentStatusUpdate) => {
                        info!(
                            "📡 [SIGNING] Broadcasting intent-status-update transaction ID {} for intent {} (round {}) - will mark intent as Solved",
                            tx_id, intent_hash, round
                        );
                        "intent_status_update"
                    }
                    Some(crate::types::TransactionType::Refund) => {
                        info!(
                            "📡 [SIGNING] Broadcasting refund transaction ID {} for intent {} (round {}) - storage will be handled by message handler",
                            tx_id, intent_hash, round
                        );
                        "refund"
                    }
                    Some(crate::types::TransactionType::WithdrawLiquidity) => {
                        // Withdraw liquidity transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] WithdrawLiquidity transaction type found with intent_hash - this is invalid."
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
                    Some(crate::types::TransactionType::ClaimRewardBtc) => {
                        // ClaimRewardBtc transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] ClaimRewardBtc transaction type found with intent_hash - this is invalid."
                        );
                        return;
                    }
                    None => {
                        // Check if this is an add_liquidity request (request_id starts with "addliq:")
                        if intent_hash.starts_with("addliq:") {
                            info!(
                                "📡 [SIGNING] Broadcasting add_liquidity transaction ID {} for request {} (round {}) - storage will be handled by message handler",
                                tx_id, intent_hash, round
                            );
                            "add_liquidity"
                        } else {
                            // This shouldn't happen if we already handled reward transactions above
                            error!(
                                "❌ [SIGNING] Transaction type is None but no solver address available and not an add_liquidity request"
                            );
                            return;
                        }
                    }
                };

                // For batch transactions (BTC and TICS NetworkToTarget), check if there are multiple intent_hashes
                // stored in intent_hashes_by_round. If so, broadcast with all intent_hashes so each one
                // gets its network_to_target_tx_id updated.
                let intent_hashes_to_broadcast = {
                    let intent_map = self.pending.intent_hashes_by_round.read().await;
                    if let Some(batch_intent_hashes) = intent_map.get(&round) {
                        // If this is a batch transaction with multiple intent_hashes, use all of them
                        if batch_intent_hashes.len() > 1 {
                            info!(
                                "📦 [SIGNING] Detected batch transaction with {} intent hashes for round {}",
                                batch_intent_hashes.len(),
                                round
                            );
                            batch_intent_hashes.clone()
                        } else {
                            // Single intent transaction, use the primary intent_hash
                            vec![intent_hash.to_string()]
                        }
                    } else {
                        // Fallback to single intent_hash if not found in map
                        vec![intent_hash.to_string()]
                    }
                };

                // Broadcast transaction ID for UserToVault, NetworkToTarget, or Refund
                if intent_hashes_to_broadcast.len() > 1 {
                    info!(
                        "📡 [SIGNING] Broadcasting transaction ID {} for batch of {} intents (type: {})",
                        tx_id, intent_hashes_to_broadcast.len(), transaction_type_str
                    );
                } else {
                    info!(
                        "📡 [SIGNING] Broadcasting transaction ID {} for intent {} (type: {})",
                        tx_id, intent_hash, transaction_type_str
                    );
                }

                self.broadcast_transaction_id(
                    intent_hashes_to_broadcast,
                    tx_id,
                    transaction_type_str,
                    None,
                )
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

                        self.broadcast_transaction_id(
                            vec![],
                            tx_id,
                            "reward_txn",
                            Some(solver_addr),
                        )
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
                    Some(crate::types::TransactionType::ClaimRewardBtc)
                ) {
                    // BTC claim-reward batch: send ClaimRewardTxIdBroadcast so handlers store tx_id on PendingClaimRewardRequest (do not mark done).
                    let claim_reward_pending_btc =
                        self.pending.claim_reward_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, identifiers, _tx_type, _extras)) =
                        claim_reward_pending_btc.get(&round)
                    {
                        let batch_requests: Vec<(String, String)> = identifiers
                            .as_ref()
                            .map(|list| {
                                list.iter()
                                    .filter_map(|encoded| {
                                        encoded.split_once('|').map(|(req_id, solver)| {
                                            (req_id.to_string(), solver.to_string())
                                        })
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        if !batch_requests.is_empty() {
                            let network_label = crate::types::network::network_type().as_str();
                            info!(
                                "📡 [SIGNING] Broadcasting BTC claim-reward txid {} for round {} with {} requests via ClaimRewardTxIdBroadcast",
                                tx_id, round, batch_requests.len()
                            );
                            let msg = crate::types::ChannelMessage::ClaimRewardTxIdBroadcast {
                                txid: tx_id.to_string(),
                                network: network_label.to_string(),
                                batch_id: format!("btc-claim-reward-round-{}", round),
                                requests: batch_requests,
                                node_id: self.id.clone(),
                            };
                            if let Err(e) = self.message_tx.send(msg).await {
                                error!(
                                    "❌ [SIGNING] Failed to send ClaimRewardTxIdBroadcast for round {}: {}",
                                    round, e
                                );
                            }
                        } else {
                            warn!(
                                "⚠️ [SIGNING] BTC ClaimReward round {} has no batch identifiers; skipping ClaimRewardTxIdBroadcast for tx_id={}",
                                round, tx_id
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [SIGNING] ClaimRewardBtc but no claim_reward_pending_transactions_btc entry for round {} (tx_id={})",
                            round, tx_id
                        );
                    }
                } else if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::WithdrawLiquidity)
                ) {
                    // Withdraw liquidity:
                    // Use a unified WithdrawTxIdBroadcast message that the network layer
                    // interprets for both BTC and TICS withdraws.
                    match txn_network {
                        crate::types::TransactionNetwork::TICS => {
                            let network_label =
                                crate::types::network::network_type().as_str().to_string();
                            let withdraw_pending =
                                self.pending.withdraw_pending_transactions_tics.read().await;
                            let batch_requests: Vec<(String, String)> = withdraw_pending
                                .get(&round)
                                .and_then(|(_, _, identifiers, _, _, _)| identifiers.as_ref())
                                .filter(|v| !v.is_empty())
                                .map(|list| {
                                    list.iter()
                                        .filter_map(|encoded| {
                                            encoded.split_once('|').map(|(req_id, solver)| {
                                                (req_id.to_string(), solver.to_string())
                                            })
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();

                            if !batch_requests.is_empty() {
                                info!(
                                    "📡 [SIGNING] Broadcasting TICS withdraw-liquidity txid {} for {} request(s) (round {}) via WithdrawTxIdBroadcast",
                                    tx_id, batch_requests.len(), round
                                );
                                let msg =
                                    crate::types::ChannelMessage::WithdrawTxIdBroadcast {
                                        txid: tx_id.to_string(),
                                        network: network_label,
                                        batch_id: format!("tics-withdraw-round-{}", round),
                                        solver_address: None,
                                        requests: batch_requests,
                                        node_id: self.id.clone(),
                                    };
                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                        "❌ [SIGNING] Failed to send WithdrawTxIdBroadcast (TICS batch) over channel for round {}: {}",
                                        round, e
                                    );
                                }
                            } else if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                                info!(
                                    "📡 [SIGNING] Broadcasting TICS withdraw-liquidity txid {} for solver {} (round {}) via WithdrawTxIdBroadcast",
                                    tx_id, solver_addr, round
                                );
                                let msg =
                                    crate::types::ChannelMessage::WithdrawTxIdBroadcast {
                                        txid: tx_id.to_string(),
                                        network: network_label,
                                        batch_id: format!("tics-withdraw-round-{}", round),
                                        solver_address: Some(solver_addr.to_string()),
                                        requests: Vec::new(),
                                        node_id: self.id.clone(),
                                    };
                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                        "❌ [SIGNING] Failed to send WithdrawTxIdBroadcast (TICS) over channel for round {}: {}",
                                        round, e
                                    );
                                }
                            } else {
                                warn!(
                                    "⚠️ [SIGNING] TICS WithdrawLiquidity round {} has no batch identifiers and no solver_address (tx_id={})",
                                    round, tx_id
                                );
                            }
                        }
                        crate::types::TransactionNetwork::BTC => {
                            // BTC withdraw: final node broadcasts txid + full batch mapping so
                            // all nodes can update their PendingWithdrawRequest.tx_id entries.
                            let withdraw_pending_transactions_btc =
                                self.pending.withdraw_pending_transactions_btc.read().await;
                            if let Some((_tx, _raw, identifiers, _tx_type, _extras)) =
                                withdraw_pending_transactions_btc.get(&round)
                            {
                                let batch_requests: Vec<(String, String)> = identifiers
                                    .as_ref()
                                    .map(|list| {
                                        list.iter()
                                            .filter_map(|encoded| {
                                                encoded.split_once('|').map(
                                                    |(req_id, solver)| {
                                                        (
                                                            req_id.to_string(),
                                                            solver.to_string(),
                                                        )
                                                    },
                                                )
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();

                                if batch_requests.is_empty() {
                                    warn!(
                                        "⚠️ [SIGNING] BTC WithdrawLiquidity round {} has no batch identifiers; skipping WithdrawTxIdBroadcast for tx_id={}",
                                        round, tx_id
                                    );
                                    return;
                                }

                                let network_label = crate::types::network::network_type().as_str();

                                info!(
                                    "📡 [SIGNING] Broadcasting BTC withdraw-liquidity txid {} for round {} with {} requests (network={}) via WithdrawTxIdBroadcast",
                                    tx_id,
                                    round,
                                    batch_requests.len(),
                                    network_label
                                );

                                let msg = crate::types::ChannelMessage::WithdrawTxIdBroadcast {
                                    txid: tx_id.to_string(),
                                    network: network_label.to_string(),
                                    batch_id: format!("btc-withdraw-round-{}", round),
                                    // BTC path uses per-request mapping; solver_address is optional
                                    solver_address: None,
                                    requests: batch_requests,
                                    node_id: self.id.clone(),
                                };

                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                        "❌ [SIGNING] Failed to send WithdrawTxIdBroadcast (BTC) over channel for round {}: {}",
                                        round, e
                                    );
                                }
                            } else {
                                warn!(
                                    "⚠️ [SIGNING] BTC WithdrawLiquidity transaction type but no withdraw_pending_transactions_btc entry for round {} (tx_id={})",
                                    round, tx_id
                                );
                            }
                        }
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
        intent_hashes: Vec<String>,
        tx_id: &str,
        transaction_type: &str,
        solver_address: Option<&str>,
    ) {
        let channel_message_transaction_id_broadcast =
            crate::types::ChannelMessage::TransactionIdBroadcast {
                intent_hashes: intent_hashes.clone(),
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
            if !intent_hashes.is_empty() {
                info!(
                    "📡 [SIGNING] Broadcasted transaction ID {} for intents {:?} (type: {}) to other nodes",
                    tx_id, intent_hashes, transaction_type
                );
            } else if let Some(solver) = solver_address {
                info!(
                    "📡 [SIGNING] Broadcasted reward transaction ID {} for solver {} (type: {}) to other nodes",
                    tx_id, solver, transaction_type
                );
            } else {
                warn!(
                    "⚠️ [SIGNING] Broadcasted transaction ID {} without intent hashes or solver address (type: {})",
                    tx_id, transaction_type
                );
            }
        }
    }

    pub(crate) async fn broadcast_transaction_error(
        &self,
        intent_hashes: Option<Vec<String>>,
        error_message: &str,
        transaction_type: &str,
        solver_address: Option<&str>,
    ) {
        let intent_hashes = intent_hashes.unwrap_or_default();
        let broadcast_message = crate::types::GossipsubMessage::TransactionErrorBroadcast {
            intent_hashes: intent_hashes.clone(),
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
            match (intent_hashes.is_empty(), solver_address) {
                (false, _) => {
                    info!(
                        "📡 [SIGNING] Broadcasted transaction error for {} intent(s) (type: {}) to other nodes: {}",
                        intent_hashes.len(), transaction_type, error_message
                    );
                }
                (true, Some(solver)) => {
                    info!(
                        "📡 [SIGNING] Broadcasted reward transaction error for solver {} (type: {}) to other nodes: {}",
                        solver, transaction_type, error_message
                    );
                }
                (true, None) => {
                    warn!(
                        "⚠️ [SIGNING] Broadcasted transaction error without intent hashes or solver address (type: {}): {}",
                        transaction_type, error_message
                    );
                }
            }
        }
    }

    /// Broadcast transaction success with request_id for sequencer tracking
    pub(crate) async fn broadcast_transaction_success(
        &self,
        sequencer_request_id: &str,
        blockchain_tx_hash: &str,
        chain_id: u64,
    ) {
        let broadcast_message = crate::types::GossipsubMessage::TransactionBroadcast {
            sequencer_request_id: Some(sequencer_request_id.to_string()),
            blockchain_tx_hash: blockchain_tx_hash.to_string(),
            chain_id,
        };

        let channel_message = crate::types::ChannelMessage::Broadcast {
            topic: "transaction-broadcast".to_string(),
            data: serde_json::to_vec(&broadcast_message).unwrap_or_default(),
        };

        if let Err(e) = self.message_tx.send(channel_message).await {
            error!(
                "❌ [SIGNING] Failed to broadcast transaction success to other nodes: {}",
                e
            );
        } else {
            info!(
                "📡 [SIGNING] Broadcasted transaction success: request_id={}, tx_hash={}, chain_id={}",
                sequencer_request_id, blockchain_tx_hash, chain_id
            );
        }
    }

    /// Broadcast transaction failure with request_id for sequencer retry
    pub(crate) async fn broadcast_transaction_failure(
        &self,
        sequencer_request_id: &str,
        blockchain_tx_hash: &str,
        error: &str,
        original_request: Option<()>,
    ) {
        let channel_message = crate::types::ChannelMessage::TransactionFailure {
            sequencer_request_id: sequencer_request_id.to_string(),
            blockchain_tx_hash: blockchain_tx_hash.to_string(),
            error: error.to_string(),
            original_request,
        };

        if let Err(e) = self.message_tx.send(channel_message).await {
            error!(
                "❌ [SIGNING] Failed to send transaction failure to channel: {}",
                e
            );
        } else {
            warn!(
                "📡 [SIGNING] Sent transaction failure to channel: request_id={}, tx_hash={}, error={}",
                sequencer_request_id, blockchain_tx_hash, error
            );
        }
    }
}
