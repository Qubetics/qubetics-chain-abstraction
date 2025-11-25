/// Shared message handlers for common patterns between channel and gossipsub handlers
///
/// This module extracts redundant code patterns to follow DRY principles and Rust best practices.
use anyhow::Result;
use tracing::{error, info, warn};

use crate::{
    types::{DepositIntent, TransactionNetwork, TransactionType},
    user_intent_manager::TransactionStatus,
};

use crate::network::transport::types::MpcNetworkLayer;

impl MpcNetworkLayer {
    /// Convert transaction type string to enum
    pub(crate) fn parse_transaction_type(tx_type_str: &str) -> Result<TransactionType> {
        match tx_type_str {
            "user_to_vault" => Ok(TransactionType::UserToVault),
            "network_to_target" => Ok(TransactionType::NetworkToTarget),
            "vault_to_network" => Ok(TransactionType::VaultToNetwork),
            "reward_txn" => Ok(TransactionType::RewardTxn),
            "withdraw_liquidity" | "withdrawLiquidity" => {
                Ok(TransactionType::WithdrawLiquidity)
            }
            _ => Err(anyhow::anyhow!("Unknown transaction type: {}", tx_type_str)),
        }
    }

    /// Get the appropriate signing key based on transaction type
    pub(crate) async fn get_signing_key_for_transaction_type(
        &self,
        transaction_type: &TransactionType,
        user_eth_address: Option<&String>,
    ) -> Option<k256::Scalar> {
        match transaction_type {
            TransactionType::UserToVault => {
                // For user deposits, use user's tweaked secret share
                self.get_signing_key_for_user(user_eth_address).await
            }
            TransactionType::NetworkToTarget => {
                // For network withdrawals, use network's DKG secret share
                if let Some(dkg_node) = &self.dkg_node {
                    dkg_node.get_final_secret_share().await
                } else {
                    None
                }
            }
            TransactionType::VaultToNetwork => {
                // For vault-to-network, use vault's tweaked secret share
                if let Some(dkg_node) = &self.dkg_node {
                    dkg_node.get_vault_tweaked_secret_share().await
                } else {
                    None
                }
            }
            TransactionType::RewardTxn => {
                // RewardTxn is not valid for intent flow - return None
                None
            }
            TransactionType::WithdrawLiquidity => {
                warn!(
                    "⚠️ [SIGNING] WithdrawLiquidity transaction type does not participate in intent signing keys"
                );
                None
            }
        }
    }

    /// Determine which chain to use based on transaction type
    pub(crate) fn get_chain_for_transaction_type(
        intent: &DepositIntent,
        transaction_type: &TransactionType,
    ) -> String {
        match transaction_type {
            TransactionType::UserToVault => intent.source_chain.to_lowercase(),
            TransactionType::NetworkToTarget => intent.target_chain.to_lowercase(),
            TransactionType::VaultToNetwork => intent.source_chain.to_lowercase(),
            TransactionType::RewardTxn => {
                // RewardTxn is not valid for intent flow - return empty string
                String::new()
            }
            TransactionType::WithdrawLiquidity => {
                warn!(
                    "⚠️ [SIGNING] WithdrawLiquidity transaction type not supported for intent routing"
                );
                String::new()
            }
        }
    }

    /// Validate transaction type for reward flow
    /// Returns Ok(()) if transaction_type is RewardTxn, Err otherwise
    pub(crate) fn validate_transaction_type_for_reward(
        transaction_type: &TransactionType,
    ) -> Result<()> {
        match transaction_type {
            TransactionType::RewardTxn => Ok(()),
            TransactionType::UserToVault
            | TransactionType::NetworkToTarget
            | TransactionType::VaultToNetwork
            | TransactionType::WithdrawLiquidity => {
                Err(anyhow::anyhow!(
                    "Transaction type {:?} is not valid for reward flow. Only RewardTxn is allowed.",
                    transaction_type
                ))
            }
        }
    }

    /// Store transaction ID based on transaction type
    pub(crate) async fn store_transaction_id_by_type(
        &self,
        user_intent_manager: &crate::user_intent_manager::UserIntentManager,
        intent_hash: &str,
        transaction_id: &str,
        transaction_type: &str,
        node_id: Option<&str>,
    ) -> Result<()> {
        match transaction_type {
            "user_to_vault" => {
                // Update solver amounts and calculate rewards for UserToVault
                if let Some(signing_node) = &self.signing_node {
                    if let Err(e) = signing_node
                        .update_solver_amounts_for_user_to_vault(intent_hash)
                        .await
                    {
                        warn!(
                            "⚠️ [SIGNING] Failed to update solver amounts for UserToVault transaction: {}",
                            e
                        );
                    } else if let Err(e) =
                        signing_node.calculate_reward_per_solver(intent_hash).await
                    {
                        warn!(
                            "⚠️ [SIGNING] Failed to calculate rewards for UserToVault transaction: {}",
                            e
                        );
                    } else {
                        info!(
                            "✅ [SIGNING] Successfully calculated rewards for UserToVault transaction: {}",
                            intent_hash
                        );
                    }
                }
                user_intent_manager
                    .store_user_to_vault_tx_id(intent_hash, transaction_id, node_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("{}", e))
            }
            "network_to_target" => user_intent_manager
                .store_network_to_target_tx_id(intent_hash, transaction_id, node_id)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e)),
            "vault_to_network" => user_intent_manager
                .store_vault_to_network_tx_id(intent_hash, transaction_id, node_id)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e)),
            "withdraw_liquidity" | "withdrawLiquidity" => {
                warn!(
                    "⚠️ [SIGNING] Received withdraw-liquidity transaction ID for intent {} but this flow is not implemented yet",
                    intent_hash
                );
                Ok(())
            }
            _ => Err(anyhow::anyhow!(
                "Unknown transaction type: {}",
                transaction_type
            )),
        }
    }

    /// Handle transaction ID storage and contract execution
    pub(crate) async fn handle_transaction_id_storage(
        &mut self,
        intent_hash: &str,
        transaction_id: &str,
        transaction_type: &str,
        node_id: &str,
    ) -> Result<()> {
        if let Some(user_intent_manager) = &self.user_intent_manager {
            // Store transaction ID
            match self
                .store_transaction_id_by_type(
                    user_intent_manager,
                    intent_hash,
                    transaction_id,
                    transaction_type,
                    Some(node_id),
                )
                .await
            {
                Ok(()) => {
                    // Store transaction status
                    if let Err(e) = user_intent_manager
                        .store_transaction_status(&transaction_id, TransactionStatus::Pending)
                        .await
                    {
                        error!(
                            "❌ [NETWORK] Failed to store transaction status for broadcast tx {}: {}",
                            transaction_id, e
                        );
                    }
                    info!(
                        "✅ [NETWORK] Successfully synchronized transaction ID {} for intent {} (type: {})",
                        transaction_id, intent_hash, transaction_type
                    );

                    // Execute contract call if needed
                    if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
                        let tx_type_enum = Self::parse_transaction_type(transaction_type)?;

                        let vault_group_key = if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_vault_group_key().await
                        } else {
                            None
                        };

                        if let Some(vault_group_key) = vault_group_key {
                            if let Err(e) = self
                                .execute_contract_call_for_transaction(
                                    &intent,
                                    intent_hash,
                                    tx_type_enum,
                                    transaction_id,
                                    Some(vault_group_key),
                                    intent.amount,
                                )
                                .await
                            {
                                warn!(
                                    "❌ [CONTRACT] Failed to execute contract call for transaction ID {}: {}",
                                    transaction_id, e
                                );
                            } else {
                                info!(
                                    "✅ [CONTRACT] Successfully executed contract call for transaction ID {}",
                                    transaction_id
                                );
                            }
                        } else {
                            warn!(
                                "❌ [CONTRACT] No vault group key available for contract call execution"
                            );
                        }
                    } else {
                        warn!(
                            "❌ [CONTRACT] Could not retrieve intent {} for contract call execution",
                            intent_hash
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "❌ [NETWORK] Failed to store synchronized transaction ID: {}",
                        e
                    );
                }
            }
        } else {
            warn!("❌ [NETWORK] No user registry available to store synchronized transaction ID");
        }
        Ok(())
    }

    /// Handle reward transaction ID storage
    pub(crate) async fn handle_reward_transaction_id_storage(
        &mut self,
        solver_address: &str,
        transaction_id: &str,
        transaction_type: &str,
    ) -> Result<()> {
        if let Some(user_intent_manager) = &self.user_intent_manager {
            let Some(network) =
                reward_network_from_tx_id(transaction_type, transaction_id)
            else {
                warn!(
                    "❌ [NETWORK] Unknown reward transaction type '{}' for tx {}; skipping storage",
                    transaction_type, transaction_id
                );
                return Ok(());
            };

            let storage_result = match network {
                TransactionNetwork::TICS => {
                    user_intent_manager
                        .add_solver_tics_txn_hash(solver_address, transaction_id.to_string())
                        .await
                }
                TransactionNetwork::BTC => {
                    user_intent_manager
                        .add_solver_btc_txn_hash(solver_address, transaction_id.to_string())
                        .await
                }
            };

            match storage_result {
                Ok(()) => {
                    // Store transaction status
                    if let Err(e) = user_intent_manager
                        .store_transaction_status(&transaction_id, TransactionStatus::Pending)
                        .await
                    {
                        error!(
                            "❌ [NETWORK] Failed to store transaction status for reward tx {}: {}",
                            transaction_id, e
                        );
                    }
                    info!(
                        "✅ [NETWORK] Successfully synchronized reward transaction ID {} for solver {} (network: {:?})",
                        transaction_id,
                        solver_address,
                        network
                    );

                    if let Err(e) = user_intent_manager
                        .set_solver_add_liquidity_txn_hash(
                            solver_address,
                            network,
                            transaction_id.to_string(),
                        )
                        .await
                    {
                        warn!(
                            "⚠️ [NETWORK] Failed to store add-liquidity txn hash for solver {}: {}",
                            solver_address, e
                        );
                    }

                    // Update claimed amounts and reduce rewards
                    if let Some(amount) = self
                        .update_reward_claims(solver_address, network, transaction_id)
                        .await?
                    {
                        let (btc_amount, tics_amount) = match network {
                            TransactionNetwork::BTC => (Some(amount), None),
                            TransactionNetwork::TICS => (None, Some(amount)),
                        };

                        let convert_amount = |value: Option<ethers::types::U256>| -> Option<u128> {
                            value.and_then(|v| {
                                if v.bits() > 128 {
                                    warn!(
                                        "⚠️ [NETWORK] Reward amount {} exceeds u128, skipping contract update",
                                        v
                                    );
                                    None
                                } else {
                                    Some(v.low_u128())
                                }
                            })
                        };

                        let btc_u128 = convert_amount(btc_amount);
                        let tics_u128 = convert_amount(tics_amount);

                        if btc_u128.is_some() || tics_u128.is_some() {
                            self.submit_solver_reward_contract_update(
                                solver_address,
                                btc_u128,
                                tics_u128,
                            )
                            .await?;
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "❌ [NETWORK] Failed to store synchronized reward transaction ID for solver {}: {}",
                        solver_address, e
                    );
                }
            }
        } else {
            warn!("❌ [NETWORK] No user registry available to store synchronized transaction ID");
        }
        Ok(())
    }

    /// Update reward claims after successful transaction
    async fn update_reward_claims(
        &self,
        solver_address: &str,
        reward_network: TransactionNetwork,
        transaction_id: &str,
    ) -> Result<Option<ethers::types::U256>> {
        if let Some(user_intent_manager) = &self.user_intent_manager {
            let (currency_label, current_reward) = match reward_network {
                TransactionNetwork::TICS => (
                    "tics",
                    user_intent_manager
                        .get_solver_reward_tics(solver_address)
                        .await
                        .unwrap_or_else(|| ethers::types::U256::zero()),
                ),
                TransactionNetwork::BTC => (
                    "btc",
                    user_intent_manager
                        .get_solver_reward_btc(solver_address)
                        .await
                        .unwrap_or_else(|| ethers::types::U256::zero()),
                ),
            };

            if current_reward > ethers::types::U256::zero() {
                // Get current claimed amount
                let current_claimed = user_intent_manager
                    .get_solver_claimed_request_amount(solver_address)
                    .await
                    .unwrap_or_else(|| ethers::types::U256::zero());

                // Update claimed amount
                let new_claimed = current_claimed + current_reward;
                if let Err(e) = user_intent_manager
                    .set_solver_claimed_request_amount(solver_address, new_claimed)
                    .await
                {
                    error!(
                        "❌ [NETWORK-REWARD] Failed to update claimed amount for solver {}: {}",
                        solver_address, e
                    );
                } else {
                    info!(
                        "✅ [NETWORK-REWARD] Updated claimed amount for solver {}: {} (was: {})",
                        solver_address, new_claimed, current_claimed
                    );
                }

                // Set reward to 0 (all rewards claimed)
                let result = match reward_network {
                    TransactionNetwork::TICS => {
                        user_intent_manager
                            .set_solver_reward_tics(solver_address, ethers::types::U256::zero())
                            .await
                    }
                    TransactionNetwork::BTC => {
                        user_intent_manager
                            .set_solver_reward_btc(solver_address, ethers::types::U256::zero())
                            .await
                    }
                };

                match result {
                    Ok(()) => {
                        info!(
                            "✅ [NETWORK-REWARD] Successfully processed {} reward transaction {} for solver {}: claimed={}, remaining_reward=0",
                            currency_label, transaction_id, solver_address, new_claimed
                        );
                        return Ok(Some(current_reward));
                    }
                    Err(e) => {
                        error!(
                            "❌ [NETWORK-REWARD] Failed to reduce {} reward for solver {}: {}",
                            currency_label, solver_address, e
                        );
                    }
                }
            } else {
                info!(
                    "ℹ️ [NETWORK-REWARD] No {} reward to claim for solver {} (already claimed or zero)",
                    currency_label, solver_address
                );
            }
        }
        Ok(None)
    }

    /// Handle withdraw liquidity transaction ID storage
    pub(crate) async fn handle_withdraw_liquidity_transaction_id_storage(
        &mut self,
        solver_address: &str,
        transaction_id: &str,
        transaction_type: &str,
    ) -> Result<()> {
        if let Some(user_intent_manager) = &self.user_intent_manager {
            let Some(network) =
                withdraw_liquidity_network_from_tx_id(transaction_type, transaction_id)
            else {
                warn!(
                    "❌ [NETWORK] Unknown withdraw liquidity transaction type '{}' for tx {}; skipping storage",
                    transaction_type, transaction_id
                );
                return Ok(());
            };

            let storage_result = match network {
                TransactionNetwork::TICS => {
                    user_intent_manager
                        .add_solver_tics_txn_hash(solver_address, transaction_id.to_string())
                        .await
                }
                TransactionNetwork::BTC => {
                    user_intent_manager
                        .add_solver_btc_txn_hash(solver_address, transaction_id.to_string())
                        .await
                }
            };

            match storage_result {
                Ok(()) => {
                    // Store transaction status
                    if let Err(e) = user_intent_manager
                        .store_transaction_status(&transaction_id, TransactionStatus::Pending)
                        .await
                    {
                        error!(
                            "❌ [NETWORK] Failed to store transaction status for withdraw liquidity tx {}: {}",
                            transaction_id, e
                        );
                    }
                    info!(
                        "✅ [NETWORK] Successfully synchronized withdraw liquidity transaction ID {} for solver {} (network: {:?})",
                        transaction_id,
                        solver_address,
                        network
                    );

                    if let Err(e) = user_intent_manager
                        .add_solver_remove_liquidity_txn_hash(
                            solver_address,
                            network,
                            transaction_id.to_string(),
                        )
                        .await
                    {
                        warn!(
                            "⚠️ [NETWORK] Failed to store remove-liquidity txn hash for solver {}: {}",
                            solver_address, e
                        );
                    }

                    info!(
                        "💧 [NETWORK] Checking pending withdraw amount for solver {} ({:?})",
                        solver_address, network
                    );
                    if let Some(amount) = self
                        .take_pending_liquidity_contract_update_amount(solver_address, network)
                        .await
                    {
                        let chain_name = match network {
                            TransactionNetwork::TICS => "qubetics",
                            TransactionNetwork::BTC => "btc",
                        };
                        info!(
                            "💧 [NETWORK] Initiating contract liquidity update for solver {} on {} amount {} after tx {}",
                            solver_address, chain_name, amount, transaction_id
                        );
                        if let Err(e) = self
                            .submit_solver_liquidity_contract_update(
                                solver_address,
                                chain_name,
                                amount,
                            )
                            .await
                        {
                            error!(
                                "❌ [NETWORK] Failed to submit contract liquidity update for solver {} after tx {}: {}",
                                solver_address, transaction_id, e
                            );
                        } else {
                            info!(
                                "✅ [NETWORK] Submitted contract liquidity update for solver {} (chain: {}, amount: {})",
                                solver_address, chain_name, amount
                            );
                        }
                    } else {
                        info!(
                            "ℹ️ [NETWORK] No pending liquidity update amount found for solver {} after tx {}; skipping contract update",
                            solver_address, transaction_id
                        );
                    }

                }
                Err(e) => {
                    error!(
                        "❌ [NETWORK] Failed to store synchronized withdraw liquidity transaction ID for solver {}: {}",
                        solver_address, e
                    );
                }
            }
        } else {
            warn!("❌ [NETWORK] No user registry available to store synchronized transaction ID");
        }
        Ok(())
    }
}

fn reward_network_from_tx_id(
    transaction_type: &str,
    transaction_id: &str,
) -> Option<TransactionNetwork> {
    match transaction_type {
        "reward_txn" => {
            if transaction_id.starts_with("0x") {
                Some(TransactionNetwork::TICS)
            } else {
                Some(TransactionNetwork::BTC)
            }
        }
        _ => None,
    }
}

fn withdraw_liquidity_network_from_tx_id(
    transaction_type: &str,
    transaction_id: &str,
) -> Option<TransactionNetwork> {
    match transaction_type {
        "withdraw_liquidity" | "withdrawLiquidity" => {
            if transaction_id.starts_with("0x") {
                Some(TransactionNetwork::TICS)
            } else {
                Some(TransactionNetwork::BTC)
            }
        }
        _ => None,
    }
}
