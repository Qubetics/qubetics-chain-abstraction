use std::sync::Arc;

use anyhow::{anyhow, Result};
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use tokio::task;
use tracing::{debug, error, info};

use super::config::{ConfigError, DatabaseConfig};
use crate::database::crypto::Cipher;
use crate::database::keystore::KeyStore;

/// Main database wrapper around RocksDB.
///
/// The core APIs are synchronous because RocksDB performs blocking disk I/O.
/// When calling these methods from async contexts, prefer the `*_async`
/// variants which delegate to a Tokio blocking task to keep the runtime
/// responsive.
#[derive(Clone)]
pub struct Database {
    db: Arc<DB>,
    cipher: Arc<Cipher>,
}

impl Database {
    /// Create a new database instance
    pub fn new(config: DatabaseConfig) -> Result<Self> {
        let config = config
            .validate()
            .map_err(|e: ConfigError| anyhow!("Invalid database configuration: {e}"))?;

        std::fs::create_dir_all(&config.path)
            .map_err(|e| anyhow!("Failed to prepare database path {}: {e}", config.path))?;

        let mut opts = Options::default();
        opts.create_if_missing(config.create_if_missing);
        opts.set_max_open_files(config.max_open_files);
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB

        let db = DB::open(&opts, &config.path)
            .map_err(|e| anyhow!("Failed to open database at {}: {}", config.path, e))?;

        info!("🗄️ [DATABASE] Opened RocksDB at: {}", config.path);

        let key_hex = config.encryption_key.as_ref().ok_or_else(|| anyhow!("Encryption key missing from config"))?;
        let key_bytes = hex::decode(key_hex).map_err(|e| anyhow!("Invalid key hex: {}", e))?;
        let cipher = Arc::new(Cipher::new(&key_bytes)?);
        info!("🔒 [DATABASE] Encryption initialized");

        Ok(Self {
            db: Arc::new(db),
            cipher,
        })
    }

    /// Store a key-value pair where both key and value are serializable
    pub fn put<K, V>(&self, key: &K, value: &V) -> Result<()>
    where
        K: Serialize,
        V: Serialize,
    {
        let key_bytes =
            bincode::serialize(key).map_err(|e| anyhow!("Failed to serialize key: {}", e))?;
        let value_bytes =
            bincode::serialize(value).map_err(|e| anyhow!("Failed to serialize value: {}", e))?;

        self.db
            .put(&key_bytes, &value_bytes)
            .map_err(|e| anyhow!("Failed to put data: {}", e))?;

        debug!(
            "🔧 [DATABASE] Stored key-value pair (key size: {}, value size: {})",
            key_bytes.len(),
            value_bytes.len()
        );
        Ok(())
    }

    /// Store a key-value pair where key is string and value is serializable
    pub fn put_string<V>(&self, key: &str, value: &V) -> Result<()>
    where
        V: Serialize,
    {
        let value_bytes =
            bincode::serialize(value).map_err(|e| anyhow!("Failed to serialize value: {}", e))?;

        self.db
            .put(key.as_bytes(), &value_bytes)
            .map_err(|e| anyhow!("Failed to put data: {}", e))?;

        debug!("🔧 [DATABASE] Stored string key-value pair: {}", key);
        Ok(())
    }

    /// Get a value by key where both key and value are deserializable
    pub fn get<K, V>(&self, key: &K) -> Result<Option<V>>
    where
        K: Serialize,
        V: for<'de> Deserialize<'de>,
    {
        let key_bytes =
            bincode::serialize(key).map_err(|e| anyhow!("Failed to serialize key: {}", e))?;

        match self.db.get(&key_bytes) {
            Ok(Some(value_bytes)) => {
                let value: V = bincode::deserialize(&value_bytes)
                    .map_err(|e| anyhow!("Failed to deserialize value: {}", e))?;
                debug!(
                    "🔍 [DATABASE] Retrieved key-value pair (value size: {})",
                    value_bytes.len()
                );
                Ok(Some(value))
            }
            Ok(None) => {
                debug!("🔍 [DATABASE] Key not found");
                Ok(None)
            }
            Err(e) => Err(anyhow!("Failed to get data: {}", e)),
        }
    }

    /// Get a value by string key where value is deserializable
    pub fn get_string<V>(&self, key: &str) -> Result<Option<V>>
    where
        V: for<'de> Deserialize<'de>,
    {
        match self.db.get(key.as_bytes()) {
            Ok(Some(value_bytes)) => {
                let value: V = bincode::deserialize(&value_bytes)
                    .map_err(|e| anyhow!("Failed to deserialize value: {}", e))?;
                debug!("🔍 [DATABASE] Retrieved string key: {}", key);
                Ok(Some(value))
            }
            Ok(None) => {
                debug!("🔍 [DATABASE] String key not found: {}", key);
                Ok(None)
            }
            Err(e) => Err(anyhow!("Failed to get data: {}", e)),
        }
    }

    /// Delete a key-value pair
    pub fn delete<K>(&self, key: &K) -> Result<()>
    where
        K: Serialize,
    {
        let key_bytes =
            bincode::serialize(key).map_err(|e| anyhow!("Failed to serialize key: {}", e))?;

        self.db
            .delete(&key_bytes)
            .map_err(|e| anyhow!("Failed to delete data: {}", e))?;

        debug!("🗑️ [DATABASE] Deleted key-value pair");
        Ok(())
    }

    /// Delete a key-value pair by string key
    pub fn delete_string(&self, key: &str) -> Result<()> {
        self.db
            .delete(key.as_bytes())
            .map_err(|e| anyhow!("Failed to delete data: {}", e))?;

        debug!("🗑️ [DATABASE] Deleted string key: {}", key);
        Ok(())
    }

    /// Store keypair bytes
    pub fn put_keypair(&self, key: &str, keypair_bytes: &[u8]) -> Result<()> {
        let final_bytes = self.cipher.encrypt(keypair_bytes)?;

        self.db
            .put(key.as_bytes(), &final_bytes)
            .map_err(|e| anyhow!("Failed to store keypair: {}", e))?;
        debug!("🔑 [DATABASE] Stored keypair with key: {}", key);
        Ok(())
    }

    /// Get keypair bytes
    pub fn get_keypair(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.db.get(key.as_bytes()) {
            Ok(Some(bytes)) => {
                let final_bytes = self.cipher.decrypt(&bytes)?;
                debug!("🔑 [DATABASE] Retrieved keypair with key: {}", key);
                Ok(Some(final_bytes))
            }
            Ok(None) => {
                debug!("🔑 [DATABASE] Keypair not found with key: {}", key);
                Ok(None)
            }
            Err(e) => Err(anyhow!("Failed to get keypair: {}", e)),
        }
    }

    /// Check if a key exists
    pub fn contains_key<K>(&self, key: &K) -> Result<bool>
    where
        K: Serialize,
    {
        let key_bytes =
            bincode::serialize(key).map_err(|e| anyhow!("Failed to serialize key: {}", e))?;

        match self.db.get(&key_bytes) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(anyhow!("Failed to check key existence: {}", e)),
        }
    }

    /// Check if a string key exists
    pub fn contains_string_key(&self, key: &str) -> Result<bool> {
        match self.db.get(key.as_bytes()) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(anyhow!("Failed to check key existence: {}", e)),
        }
    }

    /// Get all keys with a specific prefix
    pub fn get_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let prefix_bytes = prefix.as_bytes();

        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            prefix_bytes,
            rocksdb::Direction::Forward,
        ));

        for item in iter {
            let (key_bytes, _) = item.map_err(|e| anyhow!("Iterator error: {}", e))?;

            if key_bytes.starts_with(prefix_bytes) {
                if let Ok(key_str) = String::from_utf8(key_bytes.to_vec()) {
                    keys.push(key_str);
                } else {
                    continue;
                }
            } else {
                break;
            }
        }

        debug!(
            "🔍 [DATABASE] Found {} keys with prefix: {}",
            keys.len(),
            prefix
        );
        Ok(keys)
    }

    /// Asynchronous wrapper for [`Database::get_keys_with_prefix`] to avoid blocking async runtimes.
    pub async fn get_keys_with_prefix_async(&self, prefix: &str) -> Result<Vec<String>> {
        let db = self.clone();
        let prefix = prefix.to_owned();
        task::spawn_blocking(move || db.get_keys_with_prefix(&prefix))
            .await
            .map_err(|e| anyhow!("Join error during get_keys_with_prefix_async: {}", e))?
    }

    /// Get all values with a specific key prefix
    pub fn get_values_with_prefix<V>(&self, prefix: &str) -> Result<Vec<(String, V)>>
    where
        V: for<'de> Deserialize<'de>,
    {
        let mut results = Vec::new();
        let prefix_bytes = prefix.as_bytes();

        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            prefix_bytes,
            rocksdb::Direction::Forward,
        ));

        for item in iter {
            let (key_bytes, value_bytes) = item.map_err(|e| anyhow!("Iterator error: {}", e))?;

            if key_bytes.starts_with(prefix_bytes) {
                if let Ok(key_str) = String::from_utf8(key_bytes.to_vec()) {
                    match bincode::deserialize(&value_bytes) {
                        Ok(value) => results.push((key_str, value)),
                        Err(e) => {
                            error!(
                                "Failed to deserialize value for key {}: {}",
                                String::from_utf8_lossy(&key_bytes),
                                e
                            );
                            continue;
                        }
                    }
                } else {
                    continue;
                }
            } else {
                break;
            }
        }

        debug!(
            "🔍 [DATABASE] Found {} values with prefix: {}",
            results.len(),
            prefix
        );
        Ok(results)
    }

    /// Batch write operations
    pub fn batch_write<F>(&self, operations: F) -> Result<()>
    where
        F: FnOnce(&mut BatchWriter) -> Result<()>,
    {
        let mut batch_writer = BatchWriter::new();
        operations(&mut batch_writer)?;

        let op_count = batch_writer.op_count;
        let batch = batch_writer.build()?;
        self.db
            .write(batch)
            .map_err(|e| anyhow!("Failed to execute batch write: {}", e))?;

        info!(
            "🔧 [DATABASE] Executed batch write with {} operations",
            op_count
        );
        Ok(())
    }

    /// Flush database to disk
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;
        debug!("🔄 [DATABASE] Flushed database to disk");
        Ok(())
    }

    /// Export all database entries for synchronization
    pub fn export_all_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut entries = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| anyhow!("Iterator error during export: {}", e))?;
            entries.push((key.to_vec(), value.to_vec()));
        }

        info!(
            "📦 [DATABASE] Exported {} entries for synchronization",
            entries.len()
        );
        Ok(entries)
    }

    /// Export a batch of database entries
    pub fn export_batch(
        &self,
        start_index: usize,
        batch_size: usize,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, bool)> {
        let mut entries = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);

        for (i, item) in iter.enumerate() {
            if i < start_index {
                continue;
            }

            if i >= start_index + batch_size {
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

        info!(
            "📦 [DATABASE] Exported final batch of {} entries (starting at index {})",
            entries.len(),
            start_index
        );
        Ok((entries, true))
    }

    /// Count total entries in database
    pub fn count_entries(&self) -> Result<usize> {
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        let count = iter.count();
        debug!("🔢 [DATABASE] Total entries: {}", count);
        Ok(count)
    }

    /// Export database entries with specific prefix
    pub fn export_batch_with_prefix(
        &self,
        prefix: &str,
        start_index: usize,
        batch_size: usize,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, bool)> {
        let mut entries = Vec::new();
        let prefix_bytes = prefix.as_bytes();
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            prefix_bytes,
            rocksdb::Direction::Forward,
        ));

        let mut matched_index: usize = 0;
        for item in iter {
            let (key, value) =
                item.map_err(|e| anyhow!("Iterator error during filtered batch export: {}", e))?;

            if !key.starts_with(prefix_bytes) {
                break;
            }

            if matched_index < start_index {
                matched_index += 1;
                continue;
            }

            if entries.len() >= batch_size {
                info!(
                    "📦 [DATABASE] Exported filtered batch of {} user entries (index {}-{})",
                    entries.len(),
                    start_index,
                    start_index + batch_size.saturating_sub(1)
                );
                return Ok((entries, false));
            }

            entries.push((key.to_vec(), value.to_vec()));
            matched_index += 1;
        }

        info!(
            "📦 [DATABASE] Exported final filtered batch of {} user entries (starting at index {})",
            entries.len(),
            start_index
        );
        Ok((entries, true))
    }

    /// Count entries with prefix
    pub fn count_entries_with_prefix(&self, prefix: &str) -> Result<usize> {
        let keys = self.get_keys_with_prefix(prefix)?;
        let count = keys.len();
        debug!(
            "🔢 [DATABASE] Total entries with prefix '{}': {}",
            prefix, count
        );
        Ok(count)
    }

    /// Import database entries in batch
    pub fn import_batch(&self, entries: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        let batch_size = entries.len();
        let mut batch = rocksdb::WriteBatch::default();

        for (key, value) in entries {
            batch.put(&key, &value);
        }

        self.db
            .write(batch)
            .map_err(|e| anyhow!("Failed to import batch: {}", e))?;

        info!("📥 [DATABASE] Imported batch of {} entries", batch_size);
        Ok(())
    }

    /// Clear all database entries
    pub fn clear_all(&self) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, _) = item.map_err(|e| anyhow!("Iterator error during clear: {}", e))?;
            batch.delete(&key);
        }

        self.db
            .write(batch)
            .map_err(|e| anyhow!("Failed to clear database: {}", e))?;

        info!("🗑️ [DATABASE] Cleared all entries");
        Ok(())
    }

    /// Asynchronous wrapper for [`Database::get_string`] safe to call from async contexts.
    pub async fn get_string_async<V>(&self, key: &str) -> Result<Option<V>>
    where
        V: for<'de> Deserialize<'de> + Send + 'static,
    {
        let db = self.clone();
        let key = key.to_owned();
        task::spawn_blocking(move || db.get_string::<V>(&key))
            .await
            .map_err(|e| anyhow!("Join error during get_string_async: {}", e))?
    }

    /// Asynchronous wrapper for [`Database::put_string`] safe to call from async contexts.
    pub async fn put_string_async<V>(&self, key: &str, value: &V) -> Result<()>
    where
        V: Serialize + Send + Sync + 'static,
    {
        let db = self.clone();
        let key = key.to_owned();
        let value =
            bincode::serialize(value).map_err(|e| anyhow!("Failed to serialize value: {}", e))?;

        task::spawn_blocking(move || db.db.put(key.as_bytes(), &value))
            .await
            .map_err(|e| anyhow!("Join error during put_string_async: {}", e))?
            .map_err(|e| anyhow!("Failed to put data: {}", e))?;

        Ok(())
    }

    /// Asynchronous wrapper for [`Database::count_entries_with_prefix`] safe for async contexts.
    pub async fn count_entries_with_prefix_async(&self, prefix: &str) -> Result<usize> {
        let db = self.clone();
        let prefix = prefix.to_owned();
        task::spawn_blocking(move || db.count_entries_with_prefix(&prefix))
            .await
            .map_err(|e| anyhow!("Join error during count_entries_with_prefix_async: {}", e))?
    }

    /// Asynchronous wrapper for [`Database::export_batch_with_prefix`].
    pub async fn export_batch_with_prefix_async(
        &self,
        prefix: &str,
        start_index: usize,
        batch_size: usize,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, bool)> {
        let db = self.clone();
        let prefix = prefix.to_owned();
        task::spawn_blocking(move || db.export_batch_with_prefix(&prefix, start_index, batch_size))
            .await
            .map_err(|e| anyhow!("Join error during export_batch_with_prefix_async: {}", e))?
    }

    /// Asynchronous wrapper for [`Database::batch_write`] to reduce lock contention in async handlers.
    pub async fn batch_write_async<F>(&self, operations: F) -> Result<()>
    where
        F: FnOnce(&mut BatchWriter) -> Result<()> + Send + 'static,
    {
        let db = self.clone();
        task::spawn_blocking(move || db.batch_write(operations))
            .await
            .map_err(|e| anyhow!("Join error during batch_write_async: {}", e))?
    }

    /// Asynchronous wrapper for [`Database::import_batch`].
    pub async fn import_batch_async(&self, entries: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        let db = self.clone();
        task::spawn_blocking(move || db.import_batch(entries))
            .await
            .map_err(|e| anyhow!("Join error during import_batch_async: {}", e))?
    }

    /// Delete all keys matching a prefix and return the number deleted.
    pub async fn delete_keys_with_prefix_async(&self, prefix: &str) -> Result<usize> {
        let db = self.clone();
        let prefix = prefix.to_owned();
        task::spawn_blocking(move || {
            let keys = db.get_keys_with_prefix(&prefix)?;
            let count = keys.len();
            for key in &keys {
                db.delete_string(key)?;
            }
            Ok(count)
        })
        .await
        .map_err(|e| anyhow!("Join error during delete_keys_with_prefix_async: {}", e))?
    }
}

/// Implement KeyStore trait for Database
/// This allows Database to be used as a keypair storage backend
/// The trait methods delegate to the existing Database methods
impl KeyStore for Database {
    fn put_keypair(&self, key: &str, keypair_bytes: &[u8]) -> Result<()> {
        Database::put_keypair(self, key, keypair_bytes)
    }

    fn get_keypair(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Database::get_keypair(self, key)
    }
}

/// Batch writer for efficient bulk operations
pub struct BatchWriter {
    batch: rocksdb::WriteBatch,
    op_count: usize,
}

impl BatchWriter {
    fn new() -> Self {
        Self {
            batch: rocksdb::WriteBatch::default(),
            op_count: 0,
        }
    }

    /// Add a put operation to the batch
    pub fn put<K, V>(&mut self, key: &K, value: &V) -> Result<()>
    where
        K: Serialize,
        V: Serialize,
    {
        let key_bytes =
            bincode::serialize(key).map_err(|e| anyhow!("Failed to serialize key: {}", e))?;
        let value_bytes =
            bincode::serialize(value).map_err(|e| anyhow!("Failed to serialize value: {}", e))?;

        self.batch.put(&key_bytes, &value_bytes);
        self.op_count += 1;
        Ok(())
    }

    /// Add a put operation with string key to the batch
    pub fn put_string<V>(&mut self, key: &str, value: &V) -> Result<()>
    where
        V: Serialize,
    {
        let value_bytes =
            bincode::serialize(value).map_err(|e| anyhow!("Failed to serialize value: {}", e))?;

        self.batch.put(key.as_bytes(), &value_bytes);
        self.op_count += 1;
        Ok(())
    }

    /// Add a delete operation to the batch
    pub fn delete<K>(&mut self, key: &K) -> Result<()>
    where
        K: Serialize,
    {
        let key_bytes =
            bincode::serialize(key).map_err(|e| anyhow!("Failed to serialize key: {}", e))?;

        self.batch.delete(&key_bytes);
        self.op_count += 1;
        Ok(())
    }

    /// Add a delete operation with string key to the batch
    pub fn delete_string(&mut self, key: &str) -> Result<()> {
        self.batch.delete(key.as_bytes());
        self.op_count += 1;
        Ok(())
    }

    fn build(self) -> Result<rocksdb::WriteBatch> {
        Ok(self.batch)
    }
}
