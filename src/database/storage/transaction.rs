
use crate::{
    database::{
        constants::*,
        db::Database,
        keys::TransactionStatusKey,
        traits::KvStorage,
    },
    user_registry::{
        TransactionStatus,
    },
};
use anyhow::{anyhow, Result};
use chrono::Utc;
use rocksdb::DB;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, error, info};


/// Storage for tracking transaction status by hash
#[derive(Clone)]
pub struct TransactionStatusStorage {
    db: Database,
}

impl KvStorage for TransactionStatusStorage {
    fn db(&self) -> &Arc<DB> {
        self.db.db()
    }
}

impl TransactionStatusStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store status for a transaction hash
    pub async fn store_status(&self, tx_hash: &str, status: TransactionStatus) -> Result<()> {
        let key = TransactionStatusKey {
            tx_hash: tx_hash.to_string(),
        };
        info!(
            "💾 [TX_STATUS_STORAGE] Storing status for tx {}: {:?}",
            tx_hash, status
        );
        self.put(key, &status)
    }

    /// Get status for a transaction hash
    pub async fn get_status(&self, tx_hash: &str) -> Result<Option<TransactionStatus>> {
        let key = TransactionStatusKey {
            tx_hash: tx_hash.to_string(),
        };
        self.get(key)
    }

    /// Update status for a transaction hash
    pub async fn update_status(&self, tx_hash: &str, status: TransactionStatus) -> Result<()> {
        self.store_status(tx_hash, status).await
    }
}


