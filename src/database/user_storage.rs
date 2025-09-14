use crate::database::{key_utils, Database};
use crate::rpc_server::DepositIntent;
use crate::user_registry::{
    IntentStatus, IntentTransactionIds, TransactionStatus, UserRegistration,
};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tracing::{debug, error, info};

/// Database-backed user storage
#[derive(Clone)]
pub struct UserStorage {
    db: Database,
}

impl UserStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Get access to the underlying database
    pub fn get_database(&self) -> &Database {
        &self.db
    }

    /// Store a user registration
    pub async fn store_user(&self, ethereum_address: &str, user: &UserRegistration) -> Result<()> {
        let key = key_utils::user_key(ethereum_address);

        info!("💾 [USER_STORAGE] Starting to store user registration:");
        info!("  📧 Address: {}", ethereum_address);
        info!("  🆔 User ID: {}", user.user_id);
        info!("  🏗️  Registered by node: {}", user.registered_by_node);
        info!("  📅 Created at: {}", user.created_at);
        info!(
            "  🔑 Has tweaked secret share: {:?}",
            user.tweaked_secret_share
        );
        info!("  🔑 Has user group key: {}", user.user_group_key.is_some());
        info!(
            "  🏠 Has derived ETH address: {}",
            user.derived_eth_address.is_some()
        );
        info!(
            "  🪙 Has derived BTC address: {}",
            user.derived_btc_address.is_some()
        );
        info!("  📋 Intent hashes count: {}", user.intent_hashes.len());

        match self.db.put_string(&key, user) {
            Ok(()) => {
                info!(
                    "✅ [USER_STORAGE] Successfully stored user registration for: {}",
                    ethereum_address
                );
                info!("  🗄️  Database key: {}", key);
                Ok(())
            }
            Err(e) => {
                error!(
                    "❌ [USER_STORAGE] Failed to store user registration for: {}",
                    ethereum_address
                );
                error!("  🗄️  Database key: {}", key);
                error!("  💥 Error: {}", e);
                Err(e)
            }
        }
    }

    /// Get a user registration by ethereum address
    pub async fn get_user(&self, ethereum_address: &str) -> Result<Option<UserRegistration>> {
        let key = key_utils::user_key(ethereum_address);
        let user = self.db.get_string(&key)?;
        if user.is_some() {
            debug!("🔍 [USER_STORAGE] Retrieved user: {}", ethereum_address);
        }
        Ok(user)
    }

    /// Check if user exists
    pub async fn contains_user(&self, ethereum_address: &str) -> Result<bool> {
        let key = key_utils::user_key(ethereum_address);
        self.db.contains_string_key(&key)
    }

    /// Get all users
    pub async fn get_all_users(&self) -> Result<HashMap<String, UserRegistration>> {
        let prefix = crate::database::keys::USER_REGISTRATION;
        let results: Vec<(String, UserRegistration)> = self.db.get_values_with_prefix(prefix)?;

        let mut users = HashMap::new();
        for (key, user) in results {
            // Extract ethereum address from key by removing prefix
            if let Some(ethereum_address) = key.strip_prefix(prefix) {
                users.insert(ethereum_address.to_string(), user);
            }
        }

        debug!("🔍 [USER_STORAGE] Retrieved {} users", users.len());
        Ok(users)
    }

    /// Update user group key
    pub async fn update_user_group_key(
        &self,
        ethereum_address: &str,
        group_key: &crate::types::SerializablePoint,
    ) -> Result<()> {
        let key = key_utils::user_key(ethereum_address);
        if let Some(mut user) = self.get_user(ethereum_address).await? {
            user.user_group_key = Some(group_key.clone());
            self.db.put_string(&key, &user)?;
            info!(
                "✅ [USER_STORAGE] Updated group key for user: {}",
                ethereum_address
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found: {}", ethereum_address))
        }
    }

    /// Update user derived addresses
    pub async fn update_derived_addresses(
        &self,
        ethereum_address: &str,
        eth_addr: Option<String>,
        btc_addr: Option<String>,
    ) -> Result<()> {
        let key = key_utils::user_key(ethereum_address);
        if let Some(mut user) = self.get_user(ethereum_address).await? {
            if let Some(eth) = eth_addr {
                user.derived_eth_address = Some(eth);
            }
            if let Some(btc) = btc_addr {
                user.derived_btc_address = Some(btc);
            }
            self.db.put_string(&key, &user)?;
            info!(
                "✅ [USER_STORAGE] Updated derived addresses for user: {}",
                ethereum_address
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found: {}", ethereum_address))
        }
    }

    /// Store an intent hash for a user
    pub async fn store_user_intent(
        &self,
        ethereum_address: &str,
        intent_hash: &str,
        status: IntentStatus,
    ) -> Result<()> {
        let key = key_utils::user_intent_key(ethereum_address, intent_hash);

        info!("💾 [USER_STORAGE] Starting to store user intent:");
        info!("  👤 User address: {}", ethereum_address);
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  📊 Status: {:?}", status);
        info!("  🗄️  Database key: {}", key);

        match self.db.put_string(&key, &status) {
            Ok(()) => {
                info!("✅ [USER_STORAGE] Successfully stored intent status in separate record");
            }
            Err(e) => {
                error!(
                    "❌ [USER_STORAGE] Failed to store intent status in separate record: {}",
                    e
                );
                return Err(e);
            }
        }

        // Also update the user's intent_hashes map
        let user_key = key_utils::user_key(ethereum_address);
        info!("🔄 [USER_STORAGE] Updating user's intent_hashes map...");

        if let Some(mut user) = self.get_user(ethereum_address).await? {
            let old_count = user.intent_hashes.len();
            user.intent_hashes
                .insert(intent_hash.to_string(), status.clone());
            let new_count = user.intent_hashes.len();

            match self.db.put_string(&user_key, &user) {
                Ok(()) => {
                    info!("✅ [USER_STORAGE] Successfully updated user's intent_hashes map");
                    info!("  📊 Intent count: {} -> {}", old_count, new_count);
                    info!("  🔗 Added intent: {} -> {:?}", intent_hash, status);
                    Ok(())
                }
                Err(e) => {
                    error!(
                        "❌ [USER_STORAGE] Failed to update user's intent_hashes map: {}",
                        e
                    );
                    Err(e)
                }
            }
        } else {
            error!(
                "❌ [USER_STORAGE] User not found when trying to update intent_hashes: {}",
                ethereum_address
            );
            Err(anyhow::anyhow!("User not found: {}", ethereum_address))
        }
    }

    /// Get intent status for a user
    pub async fn get_user_intent_status(
        &self,
        ethereum_address: &str,
        intent_hash: &str,
    ) -> Result<Option<IntentStatus>> {
        let key = key_utils::user_intent_key(ethereum_address, intent_hash);
        self.db.get_string(&key)
    }

    /// Get all intent hashes for a user
    pub async fn get_user_intent_hashes(
        &self,
        ethereum_address: &str,
    ) -> Result<Option<HashMap<String, IntentStatus>>> {
        if let Some(user) = self.get_user(ethereum_address).await? {
            Ok(Some(user.intent_hashes))
        } else {
            Ok(None)
        }
    }
    /// Get user details by intent hash
    pub async fn get_user_by_intent_hash(
        &self,
        intent_hash: &str,
    ) -> Result<Option<UserRegistration>> {
        // Use the USER_REGISTRATION prefix from the keys module
        let user_prefix = crate::database::keys::USER_REGISTRATION;
        // List all user keys (assuming db has a list_keys method)
        let user_keys = self.db.get_keys_with_prefix(user_prefix)?;
        for user_key in user_keys {
            // user_key is like "user:0xabc...", so strip the prefix to get the address
            let address = user_key.strip_prefix(user_prefix).unwrap_or(&user_key);
            if let Some(user) = self.get_user(address).await? {
                if user.intent_hashes.contains_key(intent_hash) {
                    return Ok(Some(user));
                }
            }
        }
        Ok(None)
    }
    /// Update intent status for a user
    pub async fn update_intent_status(
        &self,
        ethereum_address: &str,
        intent_hash: &str,
        status: IntentStatus,
    ) -> Result<()> {
        // Update the separate intent status record
        let intent_key = key_utils::user_intent_key(ethereum_address, intent_hash);
        self.db.put_string(&intent_key, &status)?;

        // Update the user's intent_hashes map
        let user_key = key_utils::user_key(ethereum_address);
        if let Some(mut user) = self.get_user(ethereum_address).await? {
            user.intent_hashes
                .insert(intent_hash.to_string(), status.clone());
            self.db.put_string(&user_key, &user)?;
            info!(
                "✅ [USER_STORAGE] Updated intent status for user {}: {} -> {:?}",
                ethereum_address, intent_hash, status
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found: {}", ethereum_address))
        }
    }
    /// Get user registration details by Ethereum address
    pub async fn get_user_by_address(
        &self,
        ethereum_address: &str,
    ) -> Result<Option<UserRegistration>> {
        self.get_user(ethereum_address).await
    }
}

/// Database-backed intent storage
#[derive(Clone)]
pub struct IntentStorage {
    db: Database,
}

impl IntentStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store a deposit intent
    pub async fn store_intent(&self, intent_hash: &str, intent: &DepositIntent) -> Result<()> {
        let key = key_utils::intent_key(intent_hash);

        info!("💾 [INTENT_STORAGE] Starting to store deposit intent:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  💰 Amount: {}", intent.amount);
        info!("  🔗 Source chain: {}", intent.source_chain);
        info!("  🎯 Target chain: {}", intent.target_chain);
        info!("  📧 Target address: {}", intent.target_address);
        info!("  🗄️  Database key: {}", key);

        match self.db.put_string(&key, intent) {
            Ok(()) => {
                info!(
                    "✅ [INTENT_STORAGE] Successfully stored deposit intent: {}",
                    intent_hash
                );
                info!(
                    "  💰 Stored amount: {} for {} -> {}",
                    intent.amount, intent.source_chain, intent.target_chain
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    "❌ [INTENT_STORAGE] Failed to store deposit intent: {}",
                    intent_hash
                );
                error!("  🗄️  Database key: {}", key);
                error!("  💥 Error: {}", e);
                Err(e)
            }
        }
    }

    /// Get a deposit intent by hash
    pub async fn get_intent(&self, intent_hash: &str) -> Result<Option<DepositIntent>> {
        let key = key_utils::intent_key(intent_hash);
        let intent = self.db.get_string(&key)?;
        if intent.is_some() {
            debug!("🔍 [INTENT_STORAGE] Retrieved intent: {}", intent_hash);
        }
        Ok(intent)
    }

    /// Get all intents
    pub async fn get_all_intents(&self) -> Result<HashMap<String, DepositIntent>> {
        let prefix = crate::database::keys::INTENT_REGISTRY;
        let results: Vec<(String, DepositIntent)> = self.db.get_values_with_prefix(prefix)?;

        let mut intents = HashMap::new();
        for (key, intent) in results {
            // Extract intent hash from key by removing prefix
            if let Some(intent_hash) = key.strip_prefix(prefix) {
                intents.insert(intent_hash.to_string(), intent);
            }
        }

        debug!("🔍 [INTENT_STORAGE] Retrieved {} intents", intents.len());
        Ok(intents)
    }

    /// Delete an intent
    pub async fn delete_intent(&self, intent_hash: &str) -> Result<()> {
        let key = key_utils::intent_key(intent_hash);
        self.db.delete_string(&key)?;
        info!("🗑️ [INTENT_STORAGE] Deleted intent: {}", intent_hash);
        Ok(())
    }

    /// Get intents by status (requires checking user registrations)
    pub async fn get_intents_by_status_with_users(
        &self,
        user_storage: &UserStorage,
        status: IntentStatus,
    ) -> Result<Vec<(String, DepositIntent)>> {
        let all_users = user_storage.get_all_users().await?;
        let mut matching_intents = Vec::new();

        for (_user_addr, user) in all_users {
            for (intent_hash, intent_status) in user.intent_hashes {
                if intent_status == status {
                    if let Some(intent) = self.get_intent(&intent_hash).await? {
                        matching_intents.push((intent_hash, intent));
                    }
                }
            }
        }

        debug!(
            "🔍 [INTENT_STORAGE] Found {} intents with status: {:?}",
            matching_intents.len(),
            status
        );
        Ok(matching_intents)
    }

    /// Store transaction IDs for an intent hash
    pub async fn store_intent_transaction_ids(
        &self,
        intent_hash: &str,
        user_to_network_tx_id: Option<String>,
        network_to_target_tx_id: Option<String>,
        vault_to_network_tx_id: Option<String>,
        final_solver_id: Option<String>,
    ) -> Result<()> {
        let key = key_utils::intent_transaction_ids_key(intent_hash);

        info!("💾 [INTENT_STORAGE] Starting to store transaction IDs:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  📤 User->Network TX ID: {:?}", user_to_network_tx_id);
        info!("  📥 Network->Target TX ID: {:?}", network_to_target_tx_id);
        info!("  🏦 Vault->Network TX ID: {:?}", vault_to_network_tx_id);
        info!("  🧮 Final solver ID: {:?}", final_solver_id);
        info!("  🗄️  Database key: {}", key);

        // Check if transaction IDs already exist
        let existing_tx_ids = self.get_intent_transaction_ids(intent_hash).await?;
        let mut tx_ids = match existing_tx_ids {
            Some(existing) => {
                info!("🔄 [INTENT_STORAGE] Found existing transaction IDs, updating...");
                info!(
                    "  📤 Existing User->Network TX ID: {:?}",
                    existing.user_to_network_tx_id
                );
                info!(
                    "  📥 Existing Network->Target TX ID: {:?}",
                    existing.network_to_target_tx_id
                );
                info!("  📅 Originally created at: {}", existing.created_at);
                existing
            }
            None => {
                info!("🆕 [INTENT_STORAGE] Creating new transaction IDs record");
                IntentTransactionIds {
                    intent_hash: intent_hash.to_string(),
                    user_to_network_tx_id: None,
                    network_to_target_tx_id: None,
                    vault_to_network_tx_id: None,
                    final_solver_id: None,
                    error_message: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }
            }
        };

        let mut changes_made = false;

        // Update transaction IDs if provided
        if let Some(tx_id) = user_to_network_tx_id {
            let old_tx_id = tx_ids.user_to_network_tx_id.clone();
            tx_ids.user_to_network_tx_id = Some(tx_id.clone());
            tx_ids.updated_at = Utc::now();
            changes_made = true;

            info!(
                "📤 [INTENT_STORAGE] Updated user_to_network_tx_id for intent: {}",
                intent_hash
            );
            info!("  🔄 Old TX ID: {:?}", old_tx_id);
            info!("  🆕 New TX ID: {}", tx_id);
        }

        if let Some(tx_id) = network_to_target_tx_id {
            let old_tx_id = tx_ids.network_to_target_tx_id.clone();
            tx_ids.network_to_target_tx_id = Some(tx_id.clone());
            tx_ids.updated_at = Utc::now();
            if old_tx_id.is_none() {
                if let Some(solver) = final_solver_id.clone() {
                    tx_ids.set_final_solver(Some(solver));
                }
            }
            changes_made = true;

            info!(
                "📥 [INTENT_STORAGE] Updated network_to_target_tx_id for intent: {}",
                intent_hash
            );
            info!("  🔄 Old TX ID: {:?}", old_tx_id);
            info!("  🆕 New TX ID: {}", tx_id);
        }

        if let Some(tx_id) = vault_to_network_tx_id {
            let old_tx_id = tx_ids.vault_to_network_tx_id.clone();
            tx_ids.vault_to_network_tx_id = Some(tx_id.clone());
            tx_ids.updated_at = Utc::now();
            changes_made = true;

            info!(
                "🏦 [INTENT_STORAGE] Updated vault_to_network_tx_id for intent: {}",
                intent_hash
            );
            info!("  🔄 Old TX ID: {:?}", old_tx_id);
            info!("  🆕 New TX ID: {}", tx_id);
        }

        if final_solver_id.is_some() {
            let solver_ref = final_solver_id.as_ref().unwrap();
            let needs_update = match &tx_ids.final_solver_id {
                Some(existing) => existing != solver_ref,
                None => true,
            };
            if needs_update {
                let old_solver = tx_ids.final_solver_id.clone();
                tx_ids.final_solver_id = Some(solver_ref.clone());
                tx_ids.updated_at = Utc::now();
                changes_made = true;

                info!(
                    "🧮 [INTENT_STORAGE] Updated final_solver_id for intent: {}",
                    intent_hash
                );
                info!("  🔄 Old solver: {:?}", old_solver);
                info!("  🆕 New solver: {}", solver_ref);
            }
        }

        if !changes_made {
            info!(
                "ℹ️ [INTENT_STORAGE] No transaction IDs provided to update for intent: {}",
                intent_hash
            );
            return Ok(());
        }

        // Store the updated transaction IDs
        match self.db.put_string(&key, &tx_ids) {
            Ok(()) => {
                info!(
                    "✅ [INTENT_STORAGE] Successfully stored transaction IDs for intent: {}",
                    intent_hash
                );
                info!(
                    "  📤 Final User->Network TX ID: {:?}",
                    tx_ids.user_to_network_tx_id
                );
                info!(
                    "  📥 Final Network->Target TX ID: {:?}",
                    tx_ids.network_to_target_tx_id
                );
                info!("  📅 Updated at: {}", tx_ids.updated_at);

                // Check if both transactions are now complete
                let is_complete = tx_ids.user_to_network_tx_id.is_some()
                    && tx_ids.network_to_target_tx_id.is_some();
                if is_complete {
                    info!(
                        "🎉 [INTENT_STORAGE] Intent {} now has BOTH transaction IDs - COMPLETE!",
                        intent_hash
                    );
                } else {
                    info!(
                        "⏳ [INTENT_STORAGE] Intent {} still waiting for more transaction IDs",
                        intent_hash
                    );
                }

                Ok(())
            }
            Err(e) => {
                error!(
                    "❌ [INTENT_STORAGE] Failed to store transaction IDs for intent: {}",
                    intent_hash
                );
                error!("  🗄️  Database key: {}", key);
                error!("  💥 Error: {}", e);
                Err(e)
            }
        }
    }

    /// Get transaction IDs for an intent hash
    pub async fn get_intent_transaction_ids(
        &self,
        intent_hash: &str,
    ) -> Result<Option<IntentTransactionIds>> {
        let key = key_utils::intent_transaction_ids_key(intent_hash);
        let tx_ids = self.db.get_string(&key)?;
        if tx_ids.is_some() {
            debug!(
                "🔍 [INTENT_STORAGE] Retrieved transaction IDs for intent: {}",
                intent_hash
            );
        }
        Ok(tx_ids)
    }

    /// Store user_to_network transaction ID
    pub async fn store_user_to_network_tx_id(
        &self,
        intent_hash: &str,
        tx_id: &str,
        final_solver_id: Option<String>,
    ) -> Result<()> {
        self
            .store_intent_transaction_ids(
                intent_hash,
                Some(tx_id.to_string()),
                None,
                None,
                final_solver_id,
            ).await
    }

    /// Store network_to_target transaction ID
    pub async fn store_network_to_target_tx_id(
        &self,
        intent_hash: &str,
        tx_id: &str,
        final_solver_id: Option<String>,
    ) -> Result<()> {
        self
            .store_intent_transaction_ids(
                intent_hash,
                None,
                Some(tx_id.to_string()),
                None,
                final_solver_id,
            )
            .await
    }

    /// Store vault_to_network transaction ID
    pub async fn store_vault_to_network_tx_id(
        &self,
        intent_hash: &str,
        tx_id: &str,
        final_solver_id: Option<String>,
    ) -> Result<()> {
        self
            .store_intent_transaction_ids(
                intent_hash,
                None,
                None,
                Some(tx_id.to_string()),
                final_solver_id,
            ).await
    }

    /// Store or update the final solver for an intent
    pub async fn store_final_solver(
        &self,
        intent_hash: &str,
        solver: &str,
    ) -> Result<()> {
        info!(
            "💾 [INTENT_STORAGE] Storing final solver for intent {}: {}",
            intent_hash, solver
        );

        // Get existing transaction IDs or create a new record
        let mut tx_ids = match self.get_intent_transaction_ids(intent_hash).await? {
            Some(existing) => existing,
            None => IntentTransactionIds {
                intent_hash: intent_hash.to_string(),
                user_to_network_tx_id: None,
                network_to_target_tx_id: None,
                vault_to_network_tx_id: None,
                final_solver_id: None,
                error_message: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        };

        tx_ids.set_final_solver(Some(solver.to_string()));

        let key = key_utils::intent_transaction_ids_key(intent_hash);
        self.db.put_string(&key, &tx_ids)?;

        info!(
            "✅ [INTENT_STORAGE] Final solver stored for intent {}: {}",
            intent_hash, solver
        );

        Ok(())
    }

    /// Store error message for a failed transaction
    pub async fn store_transaction_error(
        &self,
        intent_hash: &str,
        error_message: &str,
        final_solver_id: Option<String>,
    ) -> Result<()> {
        info!(
            "💥 [INTENT_STORAGE] Storing transaction error for intent {}: {}",
            intent_hash, error_message
        );

        // Get existing transaction IDs or create new
        let mut tx_ids = match self.get_intent_transaction_ids(intent_hash).await? {
            Some(existing) => existing,
            None => IntentTransactionIds {
                intent_hash: intent_hash.to_string(),
                user_to_network_tx_id: None,
                network_to_target_tx_id: None,
                vault_to_network_tx_id: None,
                final_solver_id: None,
                error_message: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        };

        // Update error message, solver id and timestamp
        tx_ids.error_message = Some(error_message.to_string());
        if let Some(solver) = final_solver_id {
            tx_ids.final_solver_id = Some(solver);
        }
        tx_ids.updated_at = Utc::now();

        // Store updated transaction IDs
        let key = key_utils::intent_transaction_ids_key(intent_hash);
        self.db.put_string(&key, &tx_ids)?;

        info!(
            "✅ [INTENT_STORAGE] Error message stored for intent {}",
            intent_hash
        );
        Ok(())
    }

    /// Get all intents with their transaction IDs
    pub async fn get_all_intents_with_transaction_ids(
        &self,
    ) -> Result<HashMap<String, (DepositIntent, Option<IntentTransactionIds>)>> {
        let all_intents = self.get_all_intents().await?;
        let mut intents_with_tx_ids = HashMap::new();

        for (intent_hash, intent) in all_intents {
            let tx_ids = self.get_intent_transaction_ids(&intent_hash).await?;
            intents_with_tx_ids.insert(intent_hash, (intent, tx_ids));
        }

        debug!(
            "🔍 [INTENT_STORAGE] Retrieved {} intents with transaction IDs",
            intents_with_tx_ids.len()
        );
        Ok(intents_with_tx_ids)
    }

    /// Get intents that have completed both transactions
    pub async fn get_completed_intents(
        &self,
    ) -> Result<Vec<(String, DepositIntent, IntentTransactionIds)>> {
        let prefix = crate::database::keys::INTENT_TRANSACTION_IDS;
        let tx_results: Vec<(String, IntentTransactionIds)> =
            self.db.get_values_with_prefix(prefix)?;

        let mut completed_intents = Vec::new();

        for (_key, tx_ids) in tx_results {
            // Check if both transaction IDs are present
            if tx_ids.user_to_network_tx_id.is_some() && tx_ids.network_to_target_tx_id.is_some() {
                if let Some(intent) = self.get_intent(&tx_ids.intent_hash).await? {
                    completed_intents.push((tx_ids.intent_hash.clone(), intent, tx_ids));
                }
            }
        }

        debug!(
            "🔍 [INTENT_STORAGE] Found {} completed intents",
            completed_intents.len()
        );
        Ok(completed_intents)
    }

    /// Get intents that are missing transaction IDs
    pub async fn get_pending_transaction_intents(
        &self,
    ) -> Result<Vec<(String, DepositIntent, Option<IntentTransactionIds>)>> {
        let all_intents = self.get_all_intents().await?;
        let mut pending_intents = Vec::new();

        for (intent_hash, intent) in all_intents {
            let tx_ids = self.get_intent_transaction_ids(&intent_hash).await?;

            // Check if any transaction IDs are missing
            let is_pending = match &tx_ids {
                Some(tx) => {
                    tx.user_to_network_tx_id.is_none() || tx.network_to_target_tx_id.is_none()
                }
                None => true, // No transaction IDs recorded yet
            };

            if is_pending {
                pending_intents.push((intent_hash, intent, tx_ids));
            }
        }

        debug!(
            "🔍 [INTENT_STORAGE] Found {} intents pending transaction IDs",
            pending_intents.len()
        );
        Ok(pending_intents)
    }
}

/// Storage for tracking transaction status by hash
#[derive(Clone)]
pub struct TransactionStatusStorage {
    db: Database,
}

impl TransactionStatusStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store status for a transaction hash
    pub async fn store_status(&self, tx_hash: &str, status: TransactionStatus) -> Result<()> {
        let key = key_utils::transaction_status_key(tx_hash);
        info!(
            "💾 [TX_STATUS_STORAGE] Storing status for tx {}: {:?}",
            tx_hash, status
        );
        self.db.put_string(&key, &status)?;
        Ok(())
    }

    /// Get status for a transaction hash
    pub async fn get_status(&self, tx_hash: &str) -> Result<Option<TransactionStatus>> {
        let key = key_utils::transaction_status_key(tx_hash);
        self.db.get_string(&key)
    }

    /// Update status for a transaction hash
    pub async fn update_status(&self, tx_hash: &str, status: TransactionStatus) -> Result<()> {
        self.store_status(tx_hash, status).await
    }
}
