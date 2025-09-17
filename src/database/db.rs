
use anyhow::{anyhow, Result};
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info};

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub path: String,
    pub create_if_missing: bool,
    pub max_open_files: i32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./data/rocksdb".to_string(),
            create_if_missing: true,
            max_open_files: 1000,
        }
    }
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
}




