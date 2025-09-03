use rocksdb::{DB, Options, Error as RocksDBError};
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use tracing::{info, error, debug};

pub mod user_storage;
pub mod signing_storage;
pub mod consensus_storage;

pub use user_storage::{UserStorage, IntentStorage};
pub use signing_storage::SigningStorage;
pub use consensus_storage::{ConsensusStorage, ConsensusStats};

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
        
        Ok(Self {
            db: Arc::new(db),
        })
    }

    /// Store a key-value pair where both key and value are serializable
    pub fn put<K, V>(&self, key: &K, value: &V) -> Result<()>
    where
        K: Serialize,
        V: Serialize,
    {
        let key_bytes = bincode::serialize(key)
            .map_err(|e| anyhow!("Failed to serialize key: {}", e))?;
        let value_bytes = bincode::serialize(value)
            .map_err(|e| anyhow!("Failed to serialize value: {}", e))?;
        
        self.db.put(&key_bytes, &value_bytes)
            .map_err(|e| anyhow!("Failed to put data: {}", e))?;
        
        debug!("🔧 [DATABASE] Stored key-value pair (key size: {}, value size: {})", 
               key_bytes.len(), value_bytes.len());
        Ok(())
    }

    /// Store a key-value pair where key is string and value is serializable
    pub fn put_string<V>(&self, key: &str, value: &V) -> Result<()>
    where
        V: Serialize,
    {
        let value_bytes = bincode::serialize(value)
            .map_err(|e| anyhow!("Failed to serialize value: {}", e))?;
        
        self.db.put(key.as_bytes(), &value_bytes)
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
        let key_bytes = bincode::serialize(key)
            .map_err(|e| anyhow!("Failed to serialize key: {}", e))?;
        
        match self.db.get(&key_bytes) {
            Ok(Some(value_bytes)) => {
                let value: V = bincode::deserialize(&value_bytes)
                    .map_err(|e| anyhow!("Failed to deserialize value: {}", e))?;
                debug!("🔍 [DATABASE] Retrieved key-value pair (value size: {})", value_bytes.len());
                Ok(Some(value))
            },
            Ok(None) => {
                debug!("🔍 [DATABASE] Key not found");
                Ok(None)
            },
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
            },
            Ok(None) => {
                debug!("🔍 [DATABASE] String key not found: {}", key);
                Ok(None)
            },
            Err(e) => Err(anyhow!("Failed to get data: {}", e)),
        }
    }

    /// Delete a key-value pair
    pub fn delete<K>(&self, key: &K) -> Result<()>
    where
        K: Serialize,
    {
        let key_bytes = bincode::serialize(key)
            .map_err(|e| anyhow!("Failed to serialize key: {}", e))?;
        
        self.db.delete(&key_bytes)
            .map_err(|e| anyhow!("Failed to delete data: {}", e))?;
        
        debug!("🗑️ [DATABASE] Deleted key-value pair");
        Ok(())
    }

    /// Delete a key-value pair by string key
    pub fn delete_string(&self, key: &str) -> Result<()> {
        self.db.delete(key.as_bytes())
            .map_err(|e| anyhow!("Failed to delete data: {}", e))?;
        
        debug!("🗑️ [DATABASE] Deleted string key: {}", key);
        Ok(())
    }

    /// Check if a key exists
    pub fn contains_key<K>(&self, key: &K) -> Result<bool>
    where
        K: Serialize,
    {
        let key_bytes = bincode::serialize(key)
            .map_err(|e| anyhow!("Failed to serialize key: {}", e))?;
        
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
        
        let iter = self.db.iterator(rocksdb::IteratorMode::From(prefix_bytes, rocksdb::Direction::Forward));
        
        for item in iter {
            let (key_bytes, _) = item.map_err(|e| anyhow!("Iterator error: {}", e))?;
            
            // Check if key starts with prefix
            if key_bytes.starts_with(prefix_bytes) {
                if let Ok(key_str) = String::from_utf8(key_bytes.to_vec()) {
                    keys.push(key_str);
                } else {
                    // Skip non-UTF8 keys
                    continue;
                }
            } else {
                // We've passed the prefix range
                break;
            }
        }
        
        debug!("🔍 [DATABASE] Found {} keys with prefix: {}", keys.len(), prefix);
        Ok(keys)
    }

    /// Get all values with a specific key prefix
    pub fn get_values_with_prefix<V>(&self, prefix: &str) -> Result<Vec<(String, V)>>
    where
        V: for<'de> Deserialize<'de>,
    {
        let mut results = Vec::new();
        let prefix_bytes = prefix.as_bytes();
        
        let iter = self.db.iterator(rocksdb::IteratorMode::From(prefix_bytes, rocksdb::Direction::Forward));
        
        for item in iter {
            let (key_bytes, value_bytes) = item.map_err(|e| anyhow!("Iterator error: {}", e))?;
            
            // Check if key starts with prefix
            if key_bytes.starts_with(prefix_bytes) {
                if let Ok(key_str) = String::from_utf8(key_bytes.to_vec()) {
                    match bincode::deserialize(&value_bytes) {
                        Ok(value) => results.push((key_str, value)),
                        Err(e) => {
                            error!("Failed to deserialize value for key {}: {}", 
                                   String::from_utf8_lossy(&key_bytes), e);
                            continue;
                        }
                    }
                } else {
                    // Skip non-UTF8 keys
                    continue;
                }
            } else {
                // We've passed the prefix range
                break;
            }
        }
        
        debug!("🔍 [DATABASE] Found {} values with prefix: {}", results.len(), prefix);
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
        self.db.write(batch)
            .map_err(|e| anyhow!("Failed to execute batch write: {}", e))?;
        
        info!("🔧 [DATABASE] Executed batch write with {} operations", op_count);
        Ok(())
    }

    /// Flush database to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;
        debug!("🔄 [DATABASE] Flushed database to disk");
        Ok(())
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
        let key_bytes = bincode::serialize(key)
            .map_err(|e| anyhow!("Failed to serialize key: {}", e))?;
        let value_bytes = bincode::serialize(value)
            .map_err(|e| anyhow!("Failed to serialize value: {}", e))?;
        
        self.batch.put(&key_bytes, &value_bytes);
        self.op_count += 1;
        Ok(())
    }

    /// Add a put operation with string key to the batch
    pub fn put_string<V>(&mut self, key: &str, value: &V) -> Result<()>
    where
        V: Serialize,
    {
        let value_bytes = bincode::serialize(value)
            .map_err(|e| anyhow!("Failed to serialize value: {}", e))?;
        
        self.batch.put(key.as_bytes(), &value_bytes);
        self.op_count += 1;
        Ok(())
    }

    /// Add a delete operation to the batch
    pub fn delete<K>(&mut self, key: &K) -> Result<()>
    where
        K: Serialize,
    {
        let key_bytes = bincode::serialize(key)
            .map_err(|e| anyhow!("Failed to serialize key: {}", e))?;
        
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

/// Database key prefixes for different data types
pub mod keys {
    pub const USER_REGISTRATION: &str = "user:";
    pub const INTENT_REGISTRY: &str = "intent:";
    pub const USER_INTENT_HASH: &str = "user_intent:";
    pub const INTENT_TRANSACTION_IDS: &str = "intent_txids:";
    pub const PUBLIC_KEY: &str = "pubkey:";
    pub const SIGNATURE: &str = "sig:";
    pub const SIGNATURE_ROUND: &str = "sig_round:";
    pub const FINAL_NODE_ROUND: &str = "final_node:";
    pub const PENDING_TRANSACTION: &str = "pending_tx:";
    pub const CONSENSUS_ROUND: &str = "consensus:";
    pub const CONSENSUS_RESULT: &str = "consensus_result:";
    pub const SELECTED_NODES: &str = "selected_nodes:";
}

/// Utility functions for key generation
pub mod key_utils {
    use super::keys;
    
    pub fn user_key(ethereum_address: &str) -> String {
        format!("{}{}", keys::USER_REGISTRATION, ethereum_address)
    }
    
    pub fn intent_key(intent_hash: &str) -> String {
        format!("{}{}", keys::INTENT_REGISTRY, intent_hash)
    }
    
    pub fn user_intent_key(ethereum_address: &str, intent_hash: &str) -> String {
        format!("{}{}:{}", keys::USER_INTENT_HASH, ethereum_address, intent_hash)
    }
    
    pub fn intent_transaction_ids_key(intent_hash: &str) -> String {
        format!("{}{}", keys::INTENT_TRANSACTION_IDS, intent_hash)
    }
    
    pub fn public_key_key(node_id: &str) -> String {
        format!("{}{}", keys::PUBLIC_KEY, node_id)
    }
    
    pub fn signature_key(node_id: &str) -> String {
        format!("{}{}", keys::SIGNATURE, node_id)
    }
    
    pub fn signature_round_key(round: u64, node_id: &str) -> String {
        format!("{}{}:{}", keys::SIGNATURE_ROUND, round, node_id)
    }
    
    pub fn final_node_round_key(round: u64) -> String {
        format!("{}{}", keys::FINAL_NODE_ROUND, round)
    }
    
    pub fn pending_transaction_key(round: u64) -> String {
        format!("{}{}", keys::PENDING_TRANSACTION, round)
    }
    
    pub fn consensus_round_key(round: u64) -> String {
        format!("{}{}", keys::CONSENSUS_ROUND, round)
    }
    
    pub fn consensus_result_key(round: u64) -> String {
        format!("{}{}", keys::CONSENSUS_RESULT, round)
    }
    
    pub fn selected_nodes_key(round: u64) -> String {
        format!("{}{}", keys::SELECTED_NODES, round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use serde::{Serialize, Deserialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: u32,
        name: String,
        active: bool,
    }

    fn create_test_db() -> (Database, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = DatabaseConfig {
            path: temp_dir.path().to_string_lossy().to_string(),
            create_if_missing: true,
            max_open_files: 100,
        };
        let db = Database::new(config).unwrap();
        (db, temp_dir)
    }

    #[test]
    fn test_basic_operations() {
        let (db, _temp_dir) = create_test_db();
        
        let test_data = TestData {
            id: 1,
            name: "test".to_string(),
            active: true,
        };
        
        // Test put and get
        db.put_string("test_key", &test_data).unwrap();
        let retrieved: Option<TestData> = db.get_string("test_key").unwrap();
        assert_eq!(retrieved, Some(test_data.clone()));
        
        // Test contains
        assert!(db.contains_string_key("test_key").unwrap());
        assert!(!db.contains_string_key("nonexistent").unwrap());
        
        // Test delete
        db.delete_string("test_key").unwrap();
        let retrieved: Option<TestData> = db.get_string("test_key").unwrap();
        assert_eq!(retrieved, None);
    }

    #[test]
    fn test_prefix_operations() {
        let (db, _temp_dir) = create_test_db();
        
        let test_data1 = TestData { id: 1, name: "test1".to_string(), active: true };
        let test_data2 = TestData { id: 2, name: "test2".to_string(), active: false };
        
        db.put_string("prefix:key1", &test_data1).unwrap();
        db.put_string("prefix:key2", &test_data2).unwrap();
        db.put_string("other:key", &test_data1).unwrap();
        
        let keys = db.get_keys_with_prefix("prefix:").unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"prefix:key1".to_string()));
        assert!(keys.contains(&"prefix:key2".to_string()));
        
        let values: Vec<(String, TestData)> = db.get_values_with_prefix("prefix:").unwrap();
        assert_eq!(values.len(), 2);
    }
}
