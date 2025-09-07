use chrono::{DateTime, Utc};
use ff::PrimeField;
use k256::ProjectivePoint;
use k256::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use sha3::Keccak256;
use std::collections::HashMap;
use uuid::Uuid;

use super::{
    checksum_from_any, to_checksum_address, IntentStatus, IntentTransactionIds, TransactionStatus,
    UserRegistration,
};
use crate::database::{Database, IntentStorage, TransactionStatusStorage, UserStorage};
use crate::rpc_server::DepositIntent;
use crate::types::{SerializablePoint, SerializableScalar};
use crate::utils::hmac_helper::hmac256_from_addr;
use anyhow::Result;
use tracing::{error, info};

/// Database-backed user registry for managing user registrations and intent tracking
#[derive(Clone)]
pub struct DatabaseUserRegistry {
    user_storage: UserStorage,
    intent_storage: IntentStorage,
    tx_status_storage: TransactionStatusStorage,
    chain_code: [u8; 32],
}

impl DatabaseUserRegistry {
    /// Create a new database-backed user registry
    pub fn new(database: Database, chain_code: [u8; 32]) -> Self {
        let user_storage = UserStorage::new(database.clone());
        let intent_storage = IntentStorage::new(database.clone());
        let tx_status_storage = TransactionStatusStorage::new(database);

        info!("🏗️ [DB_USER_REGISTRY] Created new DatabaseUserRegistry instance");

        Self {
            user_storage,
            intent_storage,
            tx_status_storage,
            chain_code,
        }
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        ethereum_address: &str,
        dkg_secret_share: Option<&Scalar>,
        node_id: &str,
    ) -> Result<UserRegistration, String> {
        info!(
            "👤 [DB_USER_REGISTRY] register_user called - Address: {}, Node: {}",
            ethereum_address, node_id
        );

        // 1) Normalize to canonical EIP-55
        let addr_cs = match checksum_from_any(ethereum_address) {
            Ok(a) => a,
            Err(e) => {
                return Err(format!(
                    "Invalid ethereum_address '{}': {}",
                    ethereum_address, e
                ))
            }
        };

        // 2) Dedup on canonical key
        if self
            .user_storage
            .contains_user(&addr_cs)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err("User already registered".to_string());
        }

        // 3) Generate user ID and HMAC constant
        let user_id = Uuid::new_v4().to_string();
        let hmac_constant = self.generate_hmac_constant(&addr_cs);

        // 4) Create registration
        let mut registration = UserRegistration {
            user_id: user_id.clone(),
            ethereum_address: addr_cs.clone(),
            hmac_constant,
            tweaked_secret_share: None,
            user_group_key: None,
            derived_eth_address: None,
            derived_btc_address: None,
            created_at: Utc::now(),
            registered_by_node: node_id.to_string(),
            intent_hashes: HashMap::new(),
        };

        // 5) Process DKG share if provided
        if let Some(share) = dkg_secret_share {
            let tweaked_share = self.compute_tweaked_share(share, &registration.hmac_constant);
            registration.tweaked_secret_share = Some(tweaked_share);
        }

        // 6) Store in database
        info!("💾 [DB_USER_REGISTRY] Preparing to store user registration in database:");
        info!("  📧 Ethereum address: {}", addr_cs);
        info!("  🆔 User ID: {}", user_id);
        info!("  🏗️  Registered by node: {}", node_id);
        info!(
            "  🔑 Has tweaked secret share: {}",
            registration.tweaked_secret_share.is_some()
        );
        info!(
            "  🔑 Has user group key: {}",
            registration.user_group_key.is_some()
        );

        match self.user_storage.store_user(&addr_cs, &registration).await {
            Ok(()) => {
                info!("🎉 [DB_USER_REGISTRY] User registration SUCCESSFULLY stored in database!");
                info!("  📧 Final address: {}", addr_cs);
                info!("  🆔 Final user ID: {}", user_id);
                info!("  📅 Registration timestamp: {}", registration.created_at);
                info!("✅ User registration process COMPLETED for: {}", addr_cs);
                Ok(registration)
            }
            Err(e) => {
                error!("💥 [DB_USER_REGISTRY] FAILED to store user registration in database!");
                error!("  📧 Address: {}", addr_cs);
                error!("  🆔 User ID: {}", user_id);
                error!("  💥 Database error: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Get user registration by user ID
    pub async fn get_user_by_id(&self, user_id: &str) -> Option<UserRegistration> {
        // Since we store by ethereum_address, we need to search through all users
        match self.user_storage.get_all_users().await {
            Ok(users) => users
                .into_iter()
                .find(|(_, user)| user.user_id == user_id)
                .map(|(_, user)| user),
            Err(e) => {
                tracing::error!("Failed to search for user by ID {}: {}", user_id, e);
                None
            }
        }
    }

    /// Get user registration by ethereum address
    pub async fn get_user_by_address(&self, ethereum_address: &str) -> Option<UserRegistration> {
        info!(
            "🔍 [DB_USER_REGISTRY] get_user_by_address called - Address: {}",
            ethereum_address
        );

        match self.user_storage.get_user(ethereum_address).await {
            Ok(user) => {
                info!(
                    "🔍 [DB_USER_REGISTRY] get_user_by_address result - Address: {}, Found: {}",
                    ethereum_address,
                    user.is_some()
                );
                user
            }
            Err(e) => {
                tracing::error!("Failed to get user by address {}: {}", ethereum_address, e);
                None
            }
        }
    }

    /// Get all registered users
    pub async fn get_all_users(&self) -> Vec<UserRegistration> {
        match self.user_storage.get_all_users().await {
            Ok(users) => users.into_iter().map(|(_, user)| user).collect(),
            Err(e) => {
                tracing::error!("Failed to get all users: {}", e);
                Vec::new()
            }
        }
    }

    /// Get the HMAC constant for a user
    pub async fn get_hmac_constant(&self, ethereum_address: &str) -> Option<[u8; 32]> {
        if let Some(registration) = self.get_user_by_address(ethereum_address).await {
            Some(registration.hmac_constant)
        } else {
            None
        }
    }

    /// Set user group key and derived addresses
    pub async fn set_user_group_key(
        &self,
        ethereum_address: &str,
        group_key: ProjectivePoint,
    ) -> Result<(), String> {
        let affine = group_key.to_affine();
        let serial = SerializablePoint(affine);

        // Derive ETH and BTC addresses from the group key
        let derived_eth = crate::utils::get_eth_address_from_group_key(group_key);
        let derived_btc = crate::utils::get_btc_address_from_group_key(group_key);

        // Log the derived addresses
        info!(
            "📬 [DB_USER_REGISTRY] Derived ETH address for {}: {}",
            ethereum_address, derived_eth
        );
        info!(
            "📬 [DB_USER_REGISTRY] Derived BTC address for {}: {}",
            ethereum_address, derived_btc
        );

        // Update user group key in database
        self.user_storage
            .update_user_group_key(ethereum_address, &serial)
            .await
            .map_err(|e| e.to_string())?;

        // Update derived addresses
        self.user_storage
            .update_derived_addresses(ethereum_address, Some(derived_eth), Some(derived_btc))
            .await
            .map_err(|e| e.to_string())?;

        info!(
            "✅ Set user group key and derived addresses for {}",
            ethereum_address
        );
        Ok(())
    }

    /// Store intent hash mapping and the actual intent
    pub async fn store_intent_hash(
        &self,
        intent_hash: Vec<u8>,
        user_address: &str,
        deposit_intent: &DepositIntent,
    ) -> Result<(), String> {
        let intent_hash_hex = hex::encode(&intent_hash);

        info!("🔐 [DB_USER_REGISTRY] Starting intent hash storage process:");
        info!("  🔗 Intent hash (hex): {}", intent_hash_hex);
        info!("  👤 User address: {}", user_address);
        info!("  💰 Intent amount: {}", deposit_intent.amount);
        info!("  🔗 Source chain: {}", deposit_intent.source_chain);
        info!("  🎯 Target chain: {}", deposit_intent.target_chain);
        info!("  📧 Target address: {}", deposit_intent.target_address);

        // Store intent status in user registry
        info!("📋 [DB_USER_REGISTRY] Step 1: Storing intent status for user...");
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
        info!("🌐 [DB_USER_REGISTRY] Step 2: Storing intent in global registry...");
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
        ethereum_address: &str,
    ) -> Option<HashMap<String, IntentStatus>> {
        match self
            .user_storage
            .get_user_intent_hashes(ethereum_address)
            .await
        {
            Ok(hashes) => hashes,
            Err(e) => {
                tracing::error!(
                    "Failed to get intent hashes for user {}: {}",
                    ethereum_address,
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

    /// Generate HMAC constant for a user
    fn generate_hmac_constant(&self, ethereum_address: &str) -> [u8; 32] {
        hmac256_from_addr(ethereum_address, &self.chain_code)
            .expect("Failed to generate HMAC constant")
    }

    /// Compute tweaked share from DKG share and HMAC constant
    fn compute_tweaked_share(
        &self,
        share: &Scalar,
        hmac_constant: &[u8; 32],
    ) -> SerializableScalar {
        let hmac_scalar = Scalar::from_repr((*hmac_constant).into()).unwrap();
        let tweaked_scalar = *share + hmac_scalar;
        SerializableScalar(tweaked_scalar)
    }

    /// Get the chain code
    pub fn get_chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    /// Check if a user is registered
    pub async fn is_user_registered(&self, ethereum_address: &str) -> bool {
        match self.user_storage.contains_user(ethereum_address).await {
            Ok(exists) => exists,
            Err(e) => {
                tracing::error!(
                    "Failed to check if user is registered {}: {}",
                    ethereum_address,
                    e
                );
                false
            }
        }
    }

    /// Get users by registration node
    pub async fn get_users_by_node(&self, node_id: &str) -> Vec<UserRegistration> {
        match self.user_storage.get_all_users().await {
            Ok(users) => users
                .into_iter()
                .filter(|(_, user)| user.registered_by_node == node_id)
                .map(|(_, user)| user)
                .collect(),
            Err(e) => {
                tracing::error!("Failed to get users by node {}: {}", node_id, e);
                Vec::new()
            }
        }
    }

    // ==================== TRANSACTION ID MANAGEMENT ====================

    /// Store transaction ID for user_aggregated_address -> network_aggregated_address
    pub async fn store_user_to_network_tx_id(
        &self,
        intent_hash: &str,
        tx_id: &str,
    ) -> Result<(), String> {
        info!("🔗 [DB_USER_REGISTRY] Processing user_to_network transaction ID storage:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  📤 Transaction ID: {}", tx_id);
        info!("  🔄 Transaction type: user_aggregated_address -> network_aggregated_address");

        match self
            .intent_storage
            .store_user_to_network_tx_id(intent_hash, tx_id)
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
    ) -> Result<(), String> {
        info!("🔗 [DB_USER_REGISTRY] Processing network_to_target transaction ID storage:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  📥 Transaction ID: {}", tx_id);
        info!("  🔄 Transaction type: network_aggregated_address -> user_target_address");

        match self
            .intent_storage
            .store_network_to_target_tx_id(intent_hash, tx_id)
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

    /// Store both transaction IDs for an intent
    pub async fn store_intent_transaction_ids(
        &self,
        intent_hash: &str,
        user_to_network_tx_id: Option<String>,
        network_to_target_tx_id: Option<String>,
    ) -> Result<(), String> {
        self.intent_storage
            .store_intent_transaction_ids(
                intent_hash,
                user_to_network_tx_id,
                network_to_target_tx_id,
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
    ) -> Result<(), String> {
        info!("💥 [DB_USER_REGISTRY] Processing transaction error storage:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  ❌ Error message: {}", error_message);

        match self
            .intent_storage
            .store_transaction_error(intent_hash, error_message)
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
                Err(format!("Database error: {}", e))
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
    ) -> std::collections::HashMap<String, (DepositIntent, Option<IntentTransactionIds>)> {
        match self
            .intent_storage
            .get_all_intents_with_transaction_ids()
            .await
        {
            Ok(intents) => intents,
            Err(e) => {
                tracing::error!("Failed to get intents with transaction IDs: {}", e);
                std::collections::HashMap::new()
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
        info!(
            "✅ Stored transaction status for {}: {:?}",
            tx_hash, status
        );
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
