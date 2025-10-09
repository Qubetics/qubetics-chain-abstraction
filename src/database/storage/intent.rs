
use crate::{
    database::{
        constants::*,
        db::Database,
        keys::{
            IntentRegistryKey, IntentTransactionIdsKey,
        },
        traits::KvStorage,
    },
    rpc_server::DepositIntent,
    user_registry::{
        IntentStatus, IntentTransactionIds,
    },
    UserStorage
};
use anyhow::Result;
use chrono::Utc;
use rocksdb::DB;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, error, info};


/// Database-backed intent storage
#[derive(Clone)]
pub struct IntentStorage {
	db: Database,
}


impl KvStorage for IntentStorage {
    fn db(&self) -> &Arc<DB> {
        self.db.db()
    }
}





impl IntentStorage {
	pub fn new(db: Database) -> Self {
		Self { db }
	}

	/// Store a deposit intent
	pub async fn store_intent(&self, intent_hash: &str, intent: &DepositIntent) -> Result<()> {
        let key = IntentRegistryKey {
            intent_hash: intent_hash.to_string(),
        };



		info!("💾 [INTENT_STORAGE] Starting to store deposit intent:");
		info!("  🔗 Intent hash: {}", intent_hash);
		info!("  💰 Amount: {}", intent.amount);
		info!("  🔗 Source chain: {}", intent.source_chain);
		info!("  🎯 Target chain: {}", intent.target_chain);
		info!("  📧 Target address: {}", intent.target_address);
		info!("  🗄️  Database key: {:?}", key);


        match self.put(key.clone(), intent) {
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
                error!("  🗄️  Database key: {:?}", key);
                error!("  💥 Error: {}", e);
                Err(e)
            }
        }
	}

	/// Get a deposit intent by hash
    pub async fn get_intent(&self, intent_hash: &str) -> Result<Option<DepositIntent>> {
        let key = IntentRegistryKey {
            intent_hash: intent_hash.to_string(),
        };
        let intent = self.get(key)?;
        if intent.is_some() {
            debug!("🔍 [INTENT_STORAGE] Retrieved intent: {}", intent_hash);
        }
        Ok(intent)
    }

	/// Get all intents
    pub async fn get_all_intents(&self) -> Result<HashMap<String, DepositIntent>> {
        let mut intents = HashMap::new();
        let iter = self.db().prefix_iterator(INTENT_REGISTRY_PREFIX);
        for item in iter {
            let (key_bytes, value_bytes) = item?;
            if let Ok(intent) = bincode::deserialize(&value_bytes) {
                if let Some(hash_bytes) = key_bytes.strip_prefix(INTENT_REGISTRY_PREFIX) {
                    if let Ok(hash) = String::from_utf8(hash_bytes.to_vec()) {
                        intents.insert(hash, intent);
                    }
                }
            }
        }
        debug!("🔍 [INTENT_STORAGE] Retrieved {} intents", intents.len());
        Ok(intents)
    }

	/// Delete an intent
    pub async fn delete_intent(&self, intent_hash: &str) -> Result<()> {
        let key = IntentRegistryKey {
            intent_hash: intent_hash.to_string(),
        };
        self.delete(key)?;
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
        let key = IntentTransactionIdsKey {
            intent_hash: intent_hash.to_string(),
        };

		info!("💾 [INTENT_STORAGE] Starting to store transaction IDs:");
		info!("  🔗 Intent hash: {}", intent_hash);
		info!("  📤 User->Network TX ID: {:?}", user_to_network_tx_id);
		info!("  📥 Network->Target TX ID: {:?}", network_to_target_tx_id);
		info!("  🏦 Vault->Network TX ID: {:?}", vault_to_network_tx_id);
		info!("  🧮 Final solver ID: {:?}", final_solver_id);
		info!("  🗄️  Database key: {:?}", key);

		// Check if transaction IDs already exist
		let existing_tx_ids = self.get_intent_transaction_ids(intent_hash).await?;
		let mut tx_ids = match existing_tx_ids {
			Some(existing) => {
				info!("🔄 [INTENT_STORAGE] Found existing transaction IDs, updating...");
				info!("  📤 Existing User->Network TX ID: {:?}", existing.user_to_network_tx_id);
				info!(
					"  📥 Existing Network->Target TX ID: {:?}",
					existing.network_to_target_tx_id
				);
				info!("  📅 Originally created at: {}", existing.created_at);
				existing
			},
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
			},
		};

		let mut changes_made = false;

		// Update transaction IDs if provided
		if let Some(tx_id) = user_to_network_tx_id {
			let old_tx_id = tx_ids.user_to_network_tx_id.clone();
			tx_ids.user_to_network_tx_id = Some(tx_id.clone());
			tx_ids.updated_at = Utc::now();
			changes_made = true;

			info!("📤 [INTENT_STORAGE] Updated user_to_network_tx_id for intent: {}", intent_hash);
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

			info!("🏦 [INTENT_STORAGE] Updated vault_to_network_tx_id for intent: {}", intent_hash);
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

				info!("🧮 [INTENT_STORAGE] Updated final_solver_id for intent: {}", intent_hash);
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
        match self.put(key.clone(), &tx_ids) {
			Ok(()) => {
				info!(
					"✅ [INTENT_STORAGE] Successfully stored transaction IDs for intent: {}",
					intent_hash
				);
				info!("  📤 Final User->Network TX ID: {:?}", tx_ids.user_to_network_tx_id);
				info!("  📥 Final Network->Target TX ID: {:?}", tx_ids.network_to_target_tx_id);
				info!("  📅 Updated at: {}", tx_ids.updated_at);

				// Check if both transactions are now complete
				let is_complete = tx_ids.user_to_network_tx_id.is_some() &&
					tx_ids.network_to_target_tx_id.is_some();
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
			},
			Err(e) => {
				error!(
					"❌ [INTENT_STORAGE] Failed to store transaction IDs for intent: {}",
					intent_hash
				);
				error!("  💥 Error: {}", e);
				Err(e)
			},
		}
	}

	/// Get transaction IDs for an intent hash
    pub async fn get_intent_transaction_ids(
        &self,
        intent_hash: &str,
    ) -> Result<Option<IntentTransactionIds>> {
        let key = IntentTransactionIdsKey {
            intent_hash: intent_hash.to_string()
        };
        let tx_ids = self.get(key)?;
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
		self.store_intent_transaction_ids(
			intent_hash,
			Some(tx_id.to_string()),
			None,
			None,
			final_solver_id,
		)
		.await
	}

	/// Store network_to_target transaction ID
	pub async fn store_network_to_target_tx_id(
		&self,
		intent_hash: &str,
		tx_id: &str,
		final_solver_id: Option<String>,
	) -> Result<()> {
		self.store_intent_transaction_ids(
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
		self.store_intent_transaction_ids(
			intent_hash,
			None,
			None,
			Some(tx_id.to_string()),
			final_solver_id,
		)
		.await
	}

	/// Store or update the final solver for an intent
	pub async fn store_final_solver(&self, intent_hash: &str, solver: &str) -> Result<()> {
		info!("💾 [INTENT_STORAGE] Storing final solver for intent {}: {}", intent_hash, solver);

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

        let key = IntentTransactionIdsKey {
            intent_hash: intent_hash.to_string(),
        };
		self.put(key.clone(), &tx_ids)?;

		info!("✅ [INTENT_STORAGE] Final solver stored for intent {}: {}", intent_hash, solver);

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
        let key = IntentTransactionIdsKey {
            intent_hash: intent_hash.to_string(),
        };
		self.put(key, &tx_ids)?;

		info!("✅ [INTENT_STORAGE] Error message stored for intent {}", intent_hash);
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
        let mut completed_intents = Vec::new();
        let iter = self.db().prefix_iterator(INTENT_TRANSACTION_IDS_PREFIX);

        for item in iter {
            let (_key_bytes, value_bytes) = item?;
            if let Ok(tx_ids) = bincode::deserialize::<IntentTransactionIds>(&value_bytes) {
                // Check if both transaction IDs are present
                if tx_ids.user_to_network_tx_id.is_some() && tx_ids.network_to_target_tx_id.is_some() {
                    if let Some(intent) = self.get_intent(&tx_ids.intent_hash).await? {
                        completed_intents.push((tx_ids.intent_hash.clone(), intent, tx_ids));
                    }
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
				Some(tx) =>
					tx.user_to_network_tx_id.is_none() || tx.network_to_target_tx_id.is_none(),
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

