use crate::{
    database::{
        constants::*,
        db::Database,
        keys::{
            UserIntentHashKey, UserRegistrationKey,
        },
        traits::KvStorage,
    },
    user_registry::{
        IntentStatus, UserRegistration,
    },
};
use anyhow::{anyhow, Result};
use chrono::Utc;
use rocksdb::DB;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, error, info};

/// Database-backed user storage
#[derive(Clone)]
pub struct UserStorage {
    db: Database,
}

impl KvStorage for UserStorage {
    fn db(&self) -> &Arc<DB> {
        self.db.db()
    }
}

impl UserStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn get_database(&self) -> &Database {
        &self.db
    }

    /// Store a user registration
    pub async fn store_user(&self, ethereum_address: &str, user: &UserRegistration) -> Result<()> {
        let key = UserRegistrationKey {
            ethereum_address: ethereum_address.to_string(),
        };
        self.put(key, user)?;
        info!(
            "✅ [USER_STORAGE] Stored user registration for: {}",
            ethereum_address
        );
        Ok(())
    }

    /// Get a user registration by ethereum address
    pub async fn get_user(&self, ethereum_address: &str) -> Result<Option<UserRegistration>> {
        let key = UserRegistrationKey {
            ethereum_address: ethereum_address.to_string(),
        };
        let user = self.get(key)?;
        if user.is_some() {
            debug!("🔍 [USER_STORAGE] Retrieved user: {}", ethereum_address);
        }
        Ok(user)
    }

    /// Check if user exists
    pub async fn contains_user(&self, ethereum_address: &str) -> Result<bool> {
        let key = UserRegistrationKey {
            ethereum_address: ethereum_address.to_string(),
        };
        self.get::<_, UserRegistration>(key).map(|u| u.is_some())
    }

    /// Get all users
    pub async fn get_all_users(&self) -> Result<HashMap<String, UserRegistration>> {
        let mut users = HashMap::new();
        let iter = self.db().prefix_iterator(USER_REGISTRATION_PREFIX);
        for item in iter {
            let (key_bytes, value_bytes) = item?;
            if let Ok(user) = bincode::deserialize(&value_bytes) {
                if let Some(address_bytes) = key_bytes.strip_prefix(USER_REGISTRATION_PREFIX) {
                    if let Ok(address) = String::from_utf8(address_bytes.to_vec()) {
                        users.insert(address, user);
                    }
                }
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
        if let Some(mut user) = self.get_user(ethereum_address).await? {
            user.user_group_key = Some(group_key.clone());
            self.store_user(ethereum_address, &user).await?;
            info!(
                "✅ [USER_STORAGE] Updated group key for user: {}",
                ethereum_address
            );
            Ok(())
        } else {
            Err(anyhow!("User not found: {}", ethereum_address))
        }
    }

    /// Update user derived addresses
    pub async fn update_derived_addresses(
        &self,
        ethereum_address: &str,
        eth_addr: Option<String>,
        btc_addr: Option<String>,
    ) -> Result<()> {
        if let Some(mut user) = self.get_user(ethereum_address).await? {
            if let Some(eth) = eth_addr {
                user.derived_eth_address = Some(eth);
            }
            if let Some(btc) = btc_addr {
                user.derived_btc_address = Some(btc);
            }
            self.store_user(ethereum_address, &user).await?;
            info!(
                "✅ [USER_STORAGE] Updated derived addresses for user: {}",
                ethereum_address
            );
            Ok(())
        } else {
            Err(anyhow!("User not found: {}", ethereum_address))
        }
    }

    /// Store an intent hash for a user
    pub async fn store_user_intent(
        &self,
        ethereum_address: &str,
        intent_hash: &str,
        status: IntentStatus,
    ) -> Result<()> {
        let key = UserIntentHashKey {
            ethereum_address: ethereum_address.to_string(),
            intent_hash: intent_hash.to_string(),
        };
        self.put(key, &status)?;

        // Also update the user's intent_hashes map
        if let Some(mut user) = self.get_user(ethereum_address).await? {
            user.intent_hashes
                .insert(intent_hash.to_string(), status);
            self.store_user(ethereum_address, &user).await
        } else {
            error!(
                "❌ [USER_STORAGE] User not found when trying to update intent_hashes: {}",
                ethereum_address
            );
            Err(anyhow!("User not found: {}", ethereum_address))
        }
    }

    /// Get intent status for a user
    pub async fn get_user_intent_status(
        &self,
        ethereum_address: &str,
        intent_hash: &str,
    ) -> Result<Option<IntentStatus>> {
        let key = UserIntentHashKey {
            ethereum_address: ethereum_address.to_string(),
            intent_hash: intent_hash.to_string(),
        };
        self.get(key)
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
    pub async fn get_user_by_intent_hash(&self, intent_hash: &str) -> Result<Option<UserRegistration>> {
        let all_users = self.get_all_users().await?;
        for (_, user) in all_users {
            if user.intent_hashes.contains_key(intent_hash) {
                return Ok(Some(user));
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
        self.store_user_intent(ethereum_address, intent_hash, status).await
    }

    /// Get user registration details by Ethereum address
    pub async fn get_user_by_address(&self, ethereum_address: &str) -> Result<Option<UserRegistration>> {
        self.get_user(ethereum_address).await
    }
}

