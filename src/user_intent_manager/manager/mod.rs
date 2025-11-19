use chrono::Utc;
use ethereum_types::U256;
use ethers::types::U256 as EthersU256;
use ff::PrimeField;
use k256::{ProjectivePoint, Scalar};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::checksum_from_any;
use crate::database::RewardStorage;
use crate::database::{
    Database, DatabaseModule, IntentStorage, TransactionStatusStorage, UserStorage,
};
pub use crate::types::{
    DepositIntent, IntentStatus, IntentTransactionIds, SerializablePoint, SerializableScalar,
    TransactionStatus, UserRegistration,
};
use crate::utils::hmac_helper::hmac256_from_addr;
use anyhow::Result;
use tracing::info;

mod intent;
mod registration;
mod rewards;
mod transactions;

/// Database-backed user registry for managing user registrations and intent tracking
#[derive(Clone)]
pub struct UserIntentManager {
    database_module: DatabaseModule,
    user_storage: UserStorage,
    intent_storage: IntentStorage,
    tx_status_storage: TransactionStatusStorage,
    reward_storage: RewardStorage,
    chain_code: [u8; 32],
    idempotency_index: Arc<Mutex<HashMap<String, String>>>,
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
            reward_storage: database_module.reward_storage(),
            chain_code,
            idempotency_index: Arc::new(Mutex::new(HashMap::new())),
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
                "Idempotency key {} already mapped to intent {}",
                idempotency_key, existing_intent
            ));
        }

        guard.insert(idempotency_key.to_string(), intent_hash.to_string());
        Ok(false)
    }
}
