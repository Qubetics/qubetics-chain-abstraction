use chrono::Utc;
use ff::PrimeField;
use k256::{ProjectivePoint, Scalar};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::checksum_from_any;
use crate::database::{
    Database, DatabaseModule, IntentStorage, TransactionStatusStorage, UserStorage,
};
pub use crate::types::{
    DepositIntent, IntentStatus, IntentTransactionIds, SerializablePoint, SerializableScalar,
    TransactionStatus, UserRegistration,
};
use anyhow::Result;
use tracing::info;

mod intent;
mod registration;
mod transactions;

/// Database-backed user registry for managing user registrations and intent tracking.
/// Reward and liquidity data are fetched directly from the contract when required.
#[derive(Clone)]
pub struct UserIntentManager {
    database_module: DatabaseModule,
    user_storage: UserStorage,
    intent_storage: IntentStorage,
    tx_status_storage: TransactionStatusStorage,
    chain_code: [u8; 32],
    idempotency_index: Arc<Mutex<HashMap<String, String>>>,
    intent_reward_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl UserIntentManager {
    /// Get access to the underlying database
    pub fn get_database(&self) -> &Database {
        self.user_storage.get_database()
    }

    /// Create a new database-backed user registry
    pub fn new(database: Database, chain_code: [u8; 32]) -> Self {
        let module = DatabaseModule::from_database(database);
        Self::from_module(module, chain_code)
    }

    /// Create a new database registry from an aggregated module.
    pub fn from_module(database_module: DatabaseModule, chain_code: [u8; 32]) -> Self {
        info!("🏗️ [DB_USER_REGISTRY] Created new UserIntentManager instance using DatabaseModule");

        Self {
            database_module: database_module.clone(),
            user_storage: database_module.user_storage(),
            intent_storage: database_module.intent_storage(),
            tx_status_storage: database_module.transaction_status_storage(),
            chain_code,
            idempotency_index: Arc::new(Mutex::new(HashMap::new())),
            intent_reward_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn register_idempotency_key(
        &self,
        idempotency_key: &str,
        intent_hash: &str,
    ) -> Result<bool, String> {
        let mut guard = self.idempotency_index.lock().await;
        if let Some(existing_intent) = guard.get(idempotency_key) {
            if existing_intent == intent_hash {
                return Ok(true);
            }

            return Err(format!(
                "Idempotency key {idempotency_key} already mapped to intent {existing_intent}"
            ));
        }

        guard.insert(idempotency_key.to_string(), intent_hash.to_string());
        Ok(false)
    }

    pub async fn acquire_intent_reward_lock(&self, intent_hash: &str) -> Arc<Mutex<()>> {
        let mut locks = self.intent_reward_locks.lock().await;
        locks
            .entry(intent_hash.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn release_intent_reward_lock(&self, intent_hash: &str) {
        let mut locks = self.intent_reward_locks.lock().await;
        locks.remove(intent_hash);
    }
}
