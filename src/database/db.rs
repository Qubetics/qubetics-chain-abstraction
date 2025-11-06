use anyhow::{anyhow, Result};
use rocksdb::{Options, DB};
use std::sync::Arc;
use tracing::{debug, info};

use crate::database::{DkgStorage, RewardStorage, SolverStorage};

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
	pub path: String,
	pub create_if_missing: bool,
	pub max_open_files: i32,
}

/// Main database wrapper around RocksDB
#[derive(Clone)]
pub struct Database {
	db: Arc<DB>,
}

impl Database {
	pub fn db(&self) -> &Arc<DB> {
		&self.db
	}

	/// Create a new database instance
	pub fn new(config: DatabaseConfig) -> Result<Self> {
		let mut opts = Options::default();
		opts.create_if_missing(config.create_if_missing);
		opts.set_max_open_files(config.max_open_files);
		opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
		opts.set_max_write_buffer_number(3);
		opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB

		let db = DB::open(&opts, &config.path)
			.map_err(|e| anyhow!("Failed to open database at {}: {}", config.path, e))?;

		info!("🗄️ [DATABASE] Opened RocksDB at: {}", config.path);

		Ok(Self { db: Arc::new(db) })
	}

	pub fn dkg_storage(&self) -> DkgStorage {
		DkgStorage::new(self.clone())
	}

	/// Get reward storage interface
	pub fn reward_storage(&self) -> RewardStorage {
		RewardStorage::new(self.clone())
	}

	/// Get solver storage interface
	pub fn solver_storage(&self) -> SolverStorage {
		SolverStorage::new(self.clone())
	}

	/// Count total entries in database
	pub fn count_entries(&self) -> Result<usize> {
		let iter = self.db.iterator(rocksdb::IteratorMode::Start);
		let count = iter.count();
		debug!("🔢 [DATABASE] Total entries: {}", count);
		Ok(count)
	}

	/// Import database entries in batch
	/// This will overwrite existing keys
	pub fn import_batch(&self, entries: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
		let batch_size = entries.len();
		let mut batch = rocksdb::WriteBatch::default();

		for (key, value) in entries {
			batch.put(&key, &value);
		}

		self.db.write(batch).map_err(|e| anyhow!("Failed to import batch: {}", e))?;

		info!("📥 [DATABASE] Imported batch of {} entries", batch_size);
		Ok(())
	}

	/// Export a batch of database entries
	/// Returns entries from start_index to start_index + batch_size
	pub fn export_batch(
		&self,
		start_index: usize,
		batch_size: usize,
	) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, bool)> {
		let mut entries = Vec::new();
		let iter = self.db.iterator(rocksdb::IteratorMode::Start);

		// Skip to start_index
		for (i, item) in iter.enumerate() {
			if i < start_index {
				continue;
			}

			if i >= start_index + batch_size {
				// Not the last batch
				info!(
					"📦 [DATABASE] Exported batch of {} entries (index {}-{})",
					entries.len(),
					start_index,
					start_index + batch_size - 1
				);
				return Ok((entries, false));
			}

			let (key, value) =
				item.map_err(|e| anyhow!("Iterator error during batch export: {}", e))?;
			entries.push((key.to_vec(), value.to_vec()));
		}

		// If we got here, this is the last batch
		info!(
			"📦 [DATABASE] Exported final batch of {} entries (starting at index {})",
			entries.len(),
			start_index
		);
		Ok((entries, true))
	}
}
