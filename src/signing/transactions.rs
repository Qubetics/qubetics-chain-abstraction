use super::SigningNode;
use crate::{
    chain_abstraction::ChainTransaction,
    types::{intent::DepositIntent, ChannelMessage, TransactionNetwork, TransactionStatus},
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
            (chain_tx, tx_bytes, Some(solver_address), None, Some(extras)),
        );
        info!(
            "🎁 [SIGNING] Stored BTC reward transaction for round {} with solver address",
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

        match (intent_hash, &self.user_intent_manager) {
            (Some(ref intent_hash), Some(user_intent_manager)) => {
                match user_intent_manager
                    .store_transaction_error(intent_hash, error_message, None)
                    .await
                {
                    Ok(()) => {
                        info!(
                            "💥 [SIGNING] Stored transaction error for intent {} (round {}): {}",
                            intent_hash, round, error_message
                        );

                        let transaction_type_str = match transaction_type {
                            Some(crate::types::TransactionType::UserToVault) => "user_to_vault",
                            Some(crate::types::TransactionType::NetworkToTarget) => {
                                "network_to_target"
                            }
                            Some(crate::types::TransactionType::VaultToNetwork) => {
                                "vault_to_network"
                            }
                            None => "user_to_network",
                        };

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
                if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                    let transaction_type_str = match txn_network {
                        TransactionNetwork::TICS => "tics_reward",
                        TransactionNetwork::BTC => "btc_reward",
                    };

                    info!(
                        "💥 [SIGNING] Reward transaction error for solver {} (round {}): {}",
                        solver_addr, round, error_message
                    );

                    self.broadcast_transaction_error(
                        None,
                        error_message,
                        transaction_type_str,
                        Some(solver_addr),
                    )
                    .await;
                } else {
                    info!(
                        "ℹ️ [SIGNING] No solver address available for reward transaction error in round {}",
                        round
                    );
                }
            }
            _ => {
                warn!(
                    "⚠️ [SIGNING] No user registry available, cannot store transaction error for round {}",
                    round
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

        info!(
            "📋 [SIGNING-REFUND] Found intent - Amount: {}, Source: {} ({}), Target: {} ({})",
            intent.amount,
            intent.source_address,
            intent.source_chain,
            intent.target_address,
            intent.target_chain
        );

        if let Err(e) = self.broadcast_refund_initiation(intent_hash, &intent).await {
            warn!(
                "⚠️ [SIGNING-REFUND] Failed to broadcast refund initiation: {}",
                e
            );
        }

        Ok(())
    }

    async fn broadcast_refund_initiation(
        &self,
        intent_hash: &str,
        intent: &DepositIntent,
    ) -> Result<()> {
        let refund_msg = serde_json::json!({
            "type": "refund_initiation",
            "intent_hash": intent_hash,
            "source_address": intent.source_address,
            "source_chain": intent.source_chain,
            "amount": intent.amount.to_string(),
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
        let is_reward_round = {
            let reward_rounds = self.pending.reward_rounds.read().await;
            reward_rounds.contains(&round)
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
                } else {
                    let pending_transactions = self.pending.pending_transactions.read().await;
                    if let Some((_tx, _tx_bytes, intent_hash, transaction_type)) =
                        pending_transactions.get(&round)
                    {
                        (intent_hash.clone(), transaction_type.clone(), None)
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
                } else {
                    let pending_transactions_btc =
                        self.pending.pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, intent_hash, transaction_type, _extras)) =
                        pending_transactions_btc.get(&round)
                    {
                        (intent_hash.clone(), transaction_type.clone(), None)
                    } else {
                        (None, None, None)
                    }
                }
            }
        };

        match (intent_hash, &self.user_intent_manager) {
            (Some(ref intent_hash), Some(user_intent_manager)) => {
                let (transaction_type_str, storage_result) = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => {
                        let result = user_intent_manager
                            .store_user_to_vault_tx_id(intent_hash, tx_id, None)
                            .await;
                        if let Err(e) = &result {
                            error!(
                                "❌ [SIGNING] Failed to store user-to-network transaction ID for intent {}: {}",
                                intent_hash, e
                            );
                        } else {
                            info!(
                                "💾 [SIGNING] Stored user-to-network transaction ID {} for intent {} (round {})",
                                tx_id, intent_hash, round
                            );
                        }
                        ("user_to_vault", result)
                    }
                    Some(crate::types::TransactionType::NetworkToTarget) => {
                        let result = user_intent_manager
                            .store_network_to_target_tx_id(intent_hash, tx_id, Some(&self.id))
                            .await;
                        if let Err(e) = &result {
                            error!(
                                "❌ [SIGNING] Failed to store network-to-target transaction ID for intent {}: {}",
                                intent_hash, e
                            );
                        } else {
                            info!(
                                "💾 [SIGNING] Stored network-to-target transaction ID {} for intent {} (round {})",
                                tx_id, intent_hash, round
                            );
                        }
                        ("network_to_target", result)
                    }
                    Some(crate::types::TransactionType::VaultToNetwork) => {
                        let result = user_intent_manager
                            .store_vault_to_network_tx_id(intent_hash, tx_id, None)
                            .await;
                        if let Err(e) = &result {
                            error!(
                                "❌ [SIGNING] Failed to store vault-to-network transaction ID for intent {}: {}",
                                intent_hash, e
                            );
                        } else {
                            info!(
                                "💾 [SIGNING] Stored vault-to-network transaction ID {} for intent {} (round {})",
                                tx_id, intent_hash, round
                            );
                        }
                        ("vault_to_network", result)
                    }
                    None => {
                        let is_tics_reward = matches!(txn_network, TransactionNetwork::TICS);
                        let solver_address_to_use = retrieved_solver_address.as_ref();

                        if is_tics_reward {
                            if let Some(eth_addr) = solver_address_to_use {
                                let result = user_intent_manager
                                    .add_solver_tics_txn_hash(eth_addr, tx_id.to_string())
                                    .await
                                    .map_err(|e| e.to_string());
                                if let Err(e) = &result {
                                    error!(
                                        "❌ [SIGNING] Failed to store TICS reward transaction hash for solver {}: {}",
                                        eth_addr, e
                                    );
                                } else {
                                    info!(
                                        "💾 [SIGNING] Stored TICS reward transaction hash {} for solver {} (round {})",
                                        tx_id, eth_addr, round
                                    );
                                }
                                ("tics_reward", result)
                            } else {
                                error!(
                                    "❌ [SIGNING] No solver address available for TICS reward transaction storage (retrieved: {:?})",
                                    retrieved_solver_address
                                );
                                (
                                    "tics_reward",
                                    Err("No solver address available".to_string()),
                                )
                            }
                        } else if let Some(eth_addr) = solver_address_to_use {
                            let result = user_intent_manager
                                .add_solver_btc_txn_hash(eth_addr, tx_id.to_string())
                                .await
                                .map_err(|e| e.to_string());
                            if let Err(e) = &result {
                                error!(
                                    "❌ [SIGNING] Failed to store BTC reward transaction hash for solver {}: {}",
                                    eth_addr, e
                                );
                            } else {
                                info!(
                                    "💾 [SIGNING] Stored BTC reward transaction hash {} for solver {} (round {})",
                                    tx_id, eth_addr, round
                                );
                            }
                            ("btc_reward", result)
                        } else {
                            error!(
                                "❌ [SIGNING] No solver address available for BTC reward transaction storage (retrieved: {:?})",
                                retrieved_solver_address
                            );
                            ("btc_reward", Err("No solver address available".to_string()))
                        }
                    }
                };

                if storage_result.is_ok() {
                    if let Err(e) = user_intent_manager
                        .store_transaction_status(tx_id, TransactionStatus::Pending)
                        .await
                    {
                        error!(
                            "❌ [SIGNING] Failed to store transaction status for tx {}: {}",
                            tx_id, e
                        );
                    }

                    info!(
                        "✅ [SIGNING] Successfully synchronized transaction ID {} for intent {} (type: {})",
                        tx_id, intent_hash, transaction_type_str
                    );

                    self.broadcast_transaction_id(
                        Some(&intent_hash),
                        tx_id,
                        transaction_type_str,
                        None,
                    )
                    .await;
                }
            }
            (None, Some(user_intent_manager)) => {
                if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                    let (transaction_type_str, storage_result) = match txn_network {
                        TransactionNetwork::TICS => {
                            let result = user_intent_manager
                                .add_solver_tics_txn_hash(solver_addr, tx_id.to_string())
                                .await
                                .map_err(|e| e.to_string());
                            if let Err(e) = &result {
                                error!(
                                    "❌ [SIGNING] Failed to store TICS reward transaction hash for solver {}: {}",
                                    solver_addr, e
                                );
                            } else {
                                info!(
                                    "💾 [SIGNING] Stored TICS reward transaction hash {} for solver {} (round {})",
                                    tx_id, solver_addr, round
                                );
                            }
                            ("tics_reward", result)
                        }
                        TransactionNetwork::BTC => {
                            let result = user_intent_manager
                                .add_solver_btc_txn_hash(solver_addr, tx_id.to_string())
                                .await
                                .map_err(|e| e.to_string());
                            if let Err(e) = &result {
                                error!(
                                    "❌ [SIGNING] Failed to store BTC reward transaction hash for solver {}: {}",
                                    solver_addr, e
                                );
                            } else {
                                info!(
                                    "💾 [SIGNING] Stored BTC reward transaction hash {} for solver {} (round {})",
                                    tx_id, solver_addr, round
                                );
                            }
                            ("btc_reward", result)
                        }
                    };

                    if storage_result.is_ok() {
                        if let Err(e) = user_intent_manager
                            .store_transaction_status(tx_id, TransactionStatus::Pending)
                            .await
                        {
                            error!(
                                "❌ [SIGNING] Failed to store transaction status for reward tx {}: {}",
                                tx_id, e
                            );
                        }

                        info!(
                            "✅ [SIGNING] Successfully synchronized reward transaction ID {} for solver {} (type: {})",
                            tx_id, solver_addr, transaction_type_str
                        );

                        self.broadcast_transaction_id(
                            None,
                            tx_id,
                            transaction_type_str,
                            Some(solver_addr),
                        )
                        .await;
                    }
                } else {
                    info!(
                        "ℹ️ [SIGNING] No solver address available for reward transaction in round {}",
                        round
                    );
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

    pub(crate) async fn store_transaction_error_for_intent(
        &self,
        intent_hash: &str,
        error_message: &str,
    ) {
        if let Some(user_intent_manager) = &self.user_intent_manager {
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
                    "✅ [SIGNING] Stored transaction error for intent {}: {}",
                    intent_hash, error_message
                );
            }
        } else {
            warn!(
                "⚠️ [SIGNING] No user registry available to store transaction error for intent {}",
                intent_hash
            );
        }
    }
}
