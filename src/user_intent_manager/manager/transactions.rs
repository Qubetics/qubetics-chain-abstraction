use super::*;
use tracing::{error, info};

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

        match self
            .intent_storage
            .store_network_to_target_tx_id(intent_hash, tx_id, solver_id.map(|s| s.to_string()))
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Successfully stored network_to_target_tx_id");
                info!("  🎯 Intent: {}", intent_hash);
                info!("  📥 TX ID: {}", tx_id);
                Ok(())
            }
            Err(e) => {
                error!("❌ [DB_USER_REGISTRY] Failed to store network_to_target_tx_id");
                error!("  🔗 Intent hash: {}", intent_hash);
                error!("  📥 Transaction ID: {}", tx_id);
                error!("  💥 Error: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Store transaction ID for vault_address -> network_aggregated_address
    pub async fn store_vault_to_network_tx_id(
        &self,
        intent_hash: &str,
        tx_id: &str,
        solver_id: Option<&str>,
    ) -> Result<(), String> {
        info!("🔗 [DB_USER_REGISTRY] Processing vault_to_network transaction ID storage:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  🏦 Transaction ID: {}", tx_id);
        info!("  🔄 Transaction type: vault_address -> network_aggregated_address");

        match self
            .intent_storage
            .store_vault_to_network_tx_id(intent_hash, tx_id, solver_id.map(|s| s.to_string()))
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Successfully stored vault_to_network_tx_id");
                info!("  🎯 Intent: {}", intent_hash);
                info!("  🏦 TX ID: {}", tx_id);
                Ok(())
            }
            Err(e) => {
                error!("❌ [DB_USER_REGISTRY] Failed to store vault_to_network_tx_id");
                error!("  🔗 Intent hash: {}", intent_hash);
                error!("  🏦 Transaction ID: {}", tx_id);
                error!("  💥 Error: {}", e);
                Err(e.to_string())
            }
        }
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
        vault_to_network_tx_id: Option<String>,
        final_solver_id: Option<String>,
    ) -> Result<(), String> {
        self.intent_storage
            .store_intent_transaction_ids(
                intent_hash,
                user_to_network_tx_id,
                network_to_target_tx_id,
                vault_to_network_tx_id,
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
}
