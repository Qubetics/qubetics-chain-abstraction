use super::*;
use tracing::{error, info};

impl UserIntentManager {
    /// Store intent hash mapping and the actual intent
    pub async fn store_intent_hash(
        &self,
        intent_hash: Vec<u8>,
        user_address: &str,
        deposit_intent: &DepositIntent,
    ) -> Result<(), String> {
        let intent_hash_hex = hex::encode(&intent_hash);
        info!("🔐 [DB_USER_REGISTRY] Starting intent hash storage process");
        info!("  🔗 Intent hash (hex): {}", intent_hash_hex);
        info!("  👤 User address: {}", user_address);
        info!("  💰 Intent amount: {}", deposit_intent.amount);
        info!("  🔗 Source chain: {}", deposit_intent.source_chain);
        info!("  🎯 Target chain: {}", deposit_intent.target_chain);
        info!("  📧 Target address: {}", deposit_intent.target_address);

        // Store intent status in user registry
        info!("📋 [DB_USER_REGISTRY] Step 1: Storing intent status for user");
        match self
            .user_storage
            .store_user_intent(user_address, &intent_hash_hex, IntentStatus::Pending)
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Intent status stored successfully for user");
            }
            Err(e) => {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to store intent status for user: {}",
                    e
                );
                return Err(e.to_string());
            }
        }

        // Store actual intent in global registry
        info!("🌐 [DB_USER_REGISTRY] Step 2: Storing intent in global registry");
        match self
            .intent_storage
            .store_intent(&intent_hash_hex, deposit_intent)
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Intent stored successfully in global registry");
            }
            Err(e) => {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to store intent in global registry: {}",
                    e
                );
                return Err(e.to_string());
            }
        }

        info!("🎉 [DB_USER_REGISTRY] Intent hash storage process COMPLETED!");
        info!("  🔗 Intent hash: {}", intent_hash_hex);
        info!("  👤 User: {}", user_address);
        info!("  📊 Status: Pending");
        info!(
            "  💰 Amount: {} ({} -> {})",
            deposit_intent.amount, deposit_intent.source_chain, deposit_intent.target_chain
        );
        Ok(())
    }

    /// Get the user details for a given intent hash
    pub async fn get_user_by_intent_hash(&self, intent_hash: &str) -> Option<UserRegistration> {
        match self.user_storage.get_user_by_intent_hash(intent_hash).await {
            Ok(user_opt) => user_opt,
            Err(e) => {
                tracing::error!("Failed to get user by intent hash {}: {}", intent_hash, e);
                None
            }
        }
    }

    /// Get the actual DepositIntent by hash
    pub async fn get_intent(&self, intent_hash: &str) -> Option<DepositIntent> {
        match self.intent_storage.get_intent(intent_hash).await {
            Ok(intent) => intent,
            Err(e) => {
                tracing::error!("Failed to get intent {}: {}", intent_hash, e);
                None
            }
        }
    }

    /// Store target chain amount (smallest units) for an intent; computed per node from current prices
    pub async fn store_intent_target_amount(
        &self,
        intent_hash: &str,
        target_amount: u128,
    ) -> Result<(), String> {
        self.intent_storage
            .store_intent_target_amount(intent_hash, target_amount)
            .await
            .map_err(|e| e.to_string())
    }

    /// Get target chain amount for an intent, if previously computed and stored on this node
    pub async fn get_intent_target_amount(&self, intent_hash: &str) -> Option<u128> {
        self.intent_storage
            .get_intent_target_amount(intent_hash)
            .await
            .ok()
            .flatten()
    }

    /// Get all intents from global registry
    pub async fn get_all_intents(&self) -> HashMap<String, DepositIntent> {
        match self.intent_storage.get_all_intents().await {
            Ok(intents) => intents,
            Err(e) => {
                tracing::error!("Failed to get all intents: {}", e);
                HashMap::new()
            }
        }
    }

    /// Get intents by status from global registry
    pub async fn get_intents_by_status_global(
        &self,
        status: IntentStatus,
    ) -> Vec<(String, DepositIntent)> {
        match self
            .intent_storage
            .get_intents_by_status_with_users(&self.user_storage, status)
            .await
        {
            Ok(intents) => intents,
            Err(e) => {
                tracing::error!("Failed to get intents by status: {}", e);
                Vec::new()
            }
        }
    }

    /// Get intent hashes for a specific user
    pub async fn get_intent_hashes(
        &self,
        tics_address: &str,
    ) -> Option<HashMap<String, IntentStatus>> {
        match self
            .user_storage
            .get_user_intent_hashes(tics_address)
            .await
        {
            Ok(hashes) => hashes,
            Err(e) => {
                tracing::error!(
                    "Failed to get intent hashes for user {}: {}",
                    tics_address,
                    e
                );
                None
            }
        }
    }

    /// Update intent status for a user
    pub async fn update_intent_status(
        &self,
        user_address: &str,
        intent_hash: &str,
        status: IntentStatus,
    ) -> Result<(), String> {
        self.user_storage
            .update_intent_status(user_address, intent_hash, status.clone())
            .await
            .map_err(|e| e.to_string())?;
        info!(
            "✅ Updated intent status for user {}: {} -> {:?}",
            user_address, intent_hash, status
        );
        Ok(())
    }

    /// Get intent status
    pub async fn get_intent_status(
        &self,
        tics_address: &str,
        intent_hash: &str,
    ) -> Option<IntentStatus> {
        if let Some(registration) = self.get_user_by_address(tics_address).await {
            registration.intent_hashes.get(intent_hash).cloned()
        } else {
            None
        }
    }

    /// Get all intents with a specific status for a user
    pub async fn get_intents_by_status(
        &self,
        tics_address: &str,
        status: IntentStatus,
    ) -> Vec<(String, IntentStatus)> {
        if let Some(registration) = self.get_user_by_address(tics_address).await {
            registration
                .intent_hashes
                .iter()
                .filter(|(_, info)| **info == status)
                .map(|(hash, info)| (hash.clone(), info.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }
}
