use crate::{
	database::{
		constants::TRANSACTION_STATUS_PREFIX, db::Database, keys::TransactionStatusKey,
		traits::Storage,
	},
	define_storage_adapter,
	user_registry::TransactionStatus,
};
use anyhow::Result;
use tracing::info;

// Storage adapter for transaction status data
define_storage_adapter!(
	TransactionStatusAdapter,
	TransactionStatusKey,
	TransactionStatus,
	TRANSACTION_STATUS_PREFIX
);

pub type TransactionStatusStorageTyped = Storage<TransactionStatusAdapter>;

/// Storage for tracking transaction status by hash
#[derive(Clone)]
pub struct TransactionStatusStorage {
	transaction_status: TransactionStatusStorageTyped,
}

impl TransactionStatusStorage {
	pub fn new(db: Database) -> Self {
		Self { transaction_status: TransactionStatusStorageTyped::new(db) }
	}

	/// Store status for a transaction hash
	pub async fn store_status(&self, tx_hash: &str, status: TransactionStatus) -> Result<()> {
		let key = TransactionStatusKey { tx_hash: tx_hash.to_string() };
		info!("💾 [TX_STATUS_STORAGE] Storing status for tx {}: {:?}", tx_hash, status);
		self.transaction_status.put(key, &status)
	}

	/// Get status for a transaction hash
	pub async fn get_status(&self, tx_hash: &str) -> Result<Option<TransactionStatus>> {
		let key = TransactionStatusKey { tx_hash: tx_hash.to_string() };
		self.transaction_status.get(key)
	}

	/// Update status for a transaction hash
	pub async fn update_status(&self, tx_hash: &str, status: TransactionStatus) -> Result<()> {
		self.store_status(tx_hash, status).await
	}
}
