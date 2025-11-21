/// Shared message handlers for common patterns between channel and gossipsub handlers
///
/// This module extracts redundant code patterns to follow DRY principles and Rust best practices.
use anyhow::Result;
use tracing::{error, info, warn};

use crate::{
    types::{DepositIntent, TransactionType},
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
        &self,
        solver_address: &str,
        transaction_id: &str,
        transaction_type: &str,
    ) -> Result<()> {
        if let Some(user_intent_manager) = &self.user_intent_manager {
            let storage_result = match transaction_type {
                "tics_reward" => {
                    user_intent_manager
                        .add_solver_tics_txn_hash(solver_address, transaction_id.to_string())
                        .await
                }
                "btc_reward" => {
                    user_intent_manager
                        .add_solver_btc_txn_hash(solver_address, transaction_id.to_string())
                        .await
                }
                _ => {
                    warn!(
                        "❌ [NETWORK] Unknown reward transaction type: {}",
                        transaction_type
                    );
                    return Ok(());
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
                        "✅ [NETWORK] Successfully synchronized reward transaction ID {} for solver {} (type: {})",
                        transaction_id, solver_address, transaction_type
                    );

                    // Update claimed amounts and reduce rewards
                    self.update_reward_claims(solver_address, transaction_type, transaction_id)
                        .await?;
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
        transaction_type: &str,
        transaction_id: &str,
    ) -> Result<()> {
        if let Some(user_intent_manager) = &self.user_intent_manager {
            let (currency, current_reward) = if transaction_type == "tics_reward" {
                (
                    "tics",
                    user_intent_manager
                        .get_solver_reward_tics(solver_address)
                        .await
                        .unwrap_or_else(|| ethers::types::U256::zero()),
                )
            } else {
                (
                    "btc",
                    user_intent_manager
                        .get_solver_reward_btc(solver_address)
                        .await
                        .unwrap_or_else(|| ethers::types::U256::zero()),
                )
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
                let result = if currency == "tics" {
                    user_intent_manager
                        .set_solver_reward_tics(solver_address, ethers::types::U256::zero())
                        .await
                } else {
                    user_intent_manager
                        .set_solver_reward_btc(solver_address, ethers::types::U256::zero())
                        .await
                };

                match result {
                    Ok(()) => {
                        info!(
                            "✅ [NETWORK-REWARD] Successfully processed {} reward transaction {} for solver {}: claimed={}, remaining_reward=0",
                            currency, transaction_id, solver_address, new_claimed
                        );
                    }
                    Err(e) => {
                        error!(
                            "❌ [NETWORK-REWARD] Failed to reduce {} reward for solver {}: {}",
                            currency, solver_address, e
                        );
                    }
                }
            } else {
                info!(
                    "ℹ️ [NETWORK-REWARD] No {} reward to claim for solver {} (already claimed or zero)",
                    currency, solver_address
                );
            }
        }
        Ok(())
    }
}
