use anyhow::Result;
use rocksdb::{DB, Options};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

use crate::types::DepositIntent;

/// Database manager for RocksDB operations
#[derive(Clone)]
pub struct DatabaseManager {
    db: Arc<DB>,
}

/// Database column families for different data types
pub struct ColumnFamilies;

impl ColumnFamilies {
    pub const INTENTS: &'static str = "intents";
    pub const METADATA: &'static str = "metadata";
}

impl DatabaseManager {
    /// Create a new database manager with the specified path
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        info!("Initializing RocksDB at {:?}", db_path.as_ref());
        
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        
        // Define column families
        let cf_names = vec![
            ColumnFamilies::INTENTS,
            ColumnFamilies::METADATA,
        ];
        
        let db = DB::open_cf(&opts, db_path, &cf_names)?;
        
        info!("RocksDB initialized with {} column families", cf_names.len());
        
        Ok(DatabaseManager {
            db: Arc::new(db),
        })
    }
    
    /// Store a deposit intent in the database
    pub fn store_intent(&self, intent_hash: &str, intent: &DepositIntent) -> Result<()> {
        let cf = self.db.cf_handle(ColumnFamilies::INTENTS)
            .ok_or_else(|| anyhow::anyhow!("Column family 'intents' not found"))?;
        
        let serialized_intent = serde_json::to_vec(intent)?;
        self.db.put_cf(&cf, intent_hash.as_bytes(), serialized_intent)?;
        
        info!("Stored intent {}", intent_hash);
        Ok(())
    }
    
    /// Retrieve a deposit intent from the database
    pub fn get_intent(&self, intent_hash: &str) -> Result<Option<DepositIntent>> {
        let cf = self.db.cf_handle(ColumnFamilies::INTENTS)
            .ok_or_else(|| anyhow::anyhow!("Column family 'intents' not found"))?;
        
        match self.db.get_cf(&cf, intent_hash.as_bytes())? {
            Some(data) => {
                let intent: DepositIntent = serde_json::from_slice(&data)?;
                Ok(Some(intent))
            }
            None => Ok(None),
        }
    }
    
    /// List all stored intents
    pub fn list_intents(&self) -> Result<Vec<(String, DepositIntent)>> {
        let cf = self.db.cf_handle(ColumnFamilies::INTENTS)
            .ok_or_else(|| anyhow::anyhow!("Column family 'intents' not found"))?;
        
        let mut intents = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())?;
            let intent: DepositIntent = serde_json::from_slice(&value)?;
            intents.push((key_str, intent));
        }
        
        Ok(intents)
    }
    
    /// Update the status of an intent
    pub fn update_intent_status(&self, intent_hash: &str, status: &str) -> Result<()> {
        let cf = self.db.cf_handle(ColumnFamilies::METADATA)
            .ok_or_else(|| anyhow::anyhow!("Column family 'metadata' not found"))?;
        
        let status_key = format!("intent_status:{}", intent_hash);
        self.db.put_cf(&cf, status_key.as_bytes(), status.as_bytes())?;
        
        Ok(())
    }
    
    /// Get the status of an intent
    pub fn get_intent_status(&self, intent_hash: &str) -> Result<Option<String>> {
        let cf = self.db.cf_handle(ColumnFamilies::METADATA)
            .ok_or_else(|| anyhow::anyhow!("Column family 'metadata' not found"))?;
        
        let status_key = format!("intent_status:{}", intent_hash);
        match self.db.get_cf(&cf, status_key.as_bytes())? {
            Some(data) => {
                let status = String::from_utf8(data)?;
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    /// Update the solver of an intent
    pub fn update_intent_solver(&self, intent_hash: &str, solver: &str) -> Result<()> {
        let cf = self.db.cf_handle(ColumnFamilies::METADATA)
            .ok_or_else(|| anyhow::anyhow!("Column family 'metadata' not found"))?;
        
        let solver_key = format!("intent_solver:{}", intent_hash);
        self.db.put_cf(&cf, solver_key.as_bytes(), solver.as_bytes())?;
        
        info!("Updated solver for intent {} to {}", intent_hash, solver);
        Ok(())
    }
    
    /// Get the solver of an intent
    pub fn get_intent_solver(&self, intent_hash: &str) -> Result<Option<String>> {
        let cf = self.db.cf_handle(ColumnFamilies::METADATA)
            .ok_or_else(|| anyhow::anyhow!("Column family 'metadata' not found"))?;
        
        let solver_key = format!("intent_solver:{}", intent_hash);
        match self.db.get_cf(&cf, solver_key.as_bytes())? {
            Some(data) => {
                let solver = String::from_utf8(data)?;
                Ok(Some(solver))
            }
            None => Ok(None),
        }
    }
    
    /// Store arbitrary data in a specific column family
    pub fn store_data(&self, cf_name: &str, key: &str, value: &[u8]) -> Result<()> {
        let cf = self.db.cf_handle(cf_name)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf_name))?;
        
        self.db.put_cf(&cf, key.as_bytes(), value)?;
        info!("💾 Stored data in CF '{}' with key: {}", cf_name, key);
        Ok(())
    }
    
    /// Retrieve arbitrary data from a specific column family
    pub fn get_data(&self, cf_name: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(cf_name)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf_name))?;
        
        Ok(self.db.get_cf(&cf, key.as_bytes())?)
    }
    
    /// Delete data from a specific column family
    pub fn delete_data(&self, cf_name: &str, key: &str) -> Result<()> {
        let cf = self.db.cf_handle(cf_name)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf_name))?;
        
        self.db.delete_cf(&cf, key.as_bytes())?;
        info!("🗑️  Deleted data from CF '{}' with key: {}", cf_name, key);
        Ok(())
    }
    
    /// Get database statistics
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let mut stats = DatabaseStats::default();
        
        // Count intents
        if let Ok(intents) = self.list_intents() {
            stats.total_intents = intents.len();
        }
        
        // Get RocksDB internal stats
        if let Some(property) = self.db.property_value("rocksdb.stats")? {
            stats.rocksdb_stats = Some(property);
        }
        
        Ok(stats)
    }
}

/// Database statistics structure
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_intents: usize,
    pub rocksdb_stats: Option<String>,
} 