use crate::{
    database::{
        constants::{USER_REGISTRATION_PREFIX, USER_INTENT_HASH_PREFIX},
        db::Database,
        keys::{UserIntentHashKey, UserRegistrationKey},
        traits::Storage,
    },
    define_storage_adapter,
    user_registry::{IntentStatus, UserRegistration},
};
use anyhow::{anyhow, Result};
use tracing::{debug, error, info};
use std::collections::HashMap;


define_storage_adapter!(
    UserRegistrationAdapter,
    UserRegistrationKey,
    UserRegistration,
    USER_REGISTRATION_PREFIX
);

define_storage_adapter!(
    UserIntentAdapter,
    UserIntentHashKey,
    IntentStatus,
    USER_INTENT_HASH_PREFIX
);

pub type UserRegistrationStorage = Storage<UserRegistrationAdapter>;
pub type UserIntentStorage = Storage<UserIntentAdapter>;

/// Database-backed user storage
#[derive(Clone)]
pub struct UserStorage {
    user_registrations: UserRegistrationStorage,
    user_intents: UserIntentStorage,
}

impl UserStorage {
	pub fn new(db: Database) -> Self {
		Self {
            user_registrations: UserRegistrationStorage::new(db.clone()),
            user_intents: UserIntentStorage::new(db),
        }
	}

	/// Store a user registration
	pub async fn store_user(&self, ethereum_address: &str, user: &UserRegistration) -> Result<()> {
		let key = UserRegistrationKey {
            ethereum_address: ethereum_address.to_string(),
        };

		info!("💾 [USER_STORAGE] Starting to store user registration:");
		info!("  📧 Address: {}", ethereum_address);
		info!("  🆔 User ID: {}", user.user_id);
		info!("  🏗️  Registered by node: {}", user.registered_by_node);
		info!("  📅 Created at: {}", user.created_at);
		info!("  🔑 Has tweaked secret share: {:?}", user.tweaked_secret_share);
		info!("  🔑 Has user group key: {}", user.user_group_key.is_some());
		info!("  🏠 Has derived ETH address: {}", user.derived_eth_address.is_some());
		info!("  🪙 Has derived BTC address: {}", user.derived_btc_address.is_some());
		info!("  📋 Intent hashes count: {}", user.intent_hashes.len());

        self.user_registrations.put(key, user)?;
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
        let user = self.user_registrations.get(key)?;
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
        Ok(self.user_registrations.get(key)?.is_some())
    }


	/// Get all users
    pub async fn get_all_users(&self) -> Result<HashMap<String, UserRegistration>> {
        let mut users = HashMap::new();
        let kvs = self.user_registrations.get_all()?;
        for (key_bytes, user) in kvs {
            if let Ok(address) = String::from_utf8(key_bytes) {
                users.insert(address, user);
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

		info!("💾 [USER_STORAGE] Starting to store user intent:");
		info!("  👤 User address: {}", ethereum_address);
		info!("  🔗 Intent hash: {}", intent_hash);
		info!("  📊 Status: {:?}", status);
		info!("  🗄️  Database key: {:?}", key);

        self.user_intents.put(key.clone(), &status)?;

		// Also update the user's intent_hashes map
		info!("🔄 [USER_STORAGE] Updating user's intent_hashes map...");

		if let Some(mut user) = self.get_user(ethereum_address).await? {
			let old_count = user.intent_hashes.len();
			user.intent_hashes.insert(intent_hash.to_string(), status.clone());
			let new_count = user.intent_hashes.len();

            let user_key = UserRegistrationKey {
                ethereum_address: ethereum_address.to_string(),
            };
			match self.user_registrations.put(user_key, &user) {
				Ok(()) => {
					info!("✅ [USER_STORAGE] Successfully updated user's intent_hashes map");
					info!("  📊 Intent count: {} -> {}", old_count, new_count);
					info!("  🔗 Added intent: {} -> {:?}", intent_hash, status);
					Ok(())
				},
				Err(e) => {
					error!("❌ [USER_STORAGE] Failed to update user's intent_hashes map: {}", e);
					Err(e)
				},
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
        let key = UserIntentHashKey {
            ethereum_address: ethereum_address.to_string(),
            intent_hash: intent_hash.to_string(),
        };
        self.user_intents.get(key)
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



