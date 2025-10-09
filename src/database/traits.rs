use anyhow::{anyhow, Result};
use rocksdb::DB;
use serde::Serialize;
use std::sync::Arc;
use serde::de::DeserializeOwned;
use tracing::debug;

pub trait DBKey {
    /// Return the prefix 
    fn prefix(&self) -> &'static [u8];


    fn key_bytes(&self) -> Vec<u8>;

    /// Concatenating the prefix and key bytes.
    fn as_db_key(&self) -> Vec<u8> {
        [self.prefix(), &self.key_bytes()].concat()
    }
}


pub trait KvStorage {

    fn db(&self) -> &Arc<DB>;

    fn put<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: DBKey,
        V: Serialize,
    {
        self.db()
            .put(&key.as_db_key(), &bincode::serialize(value)?)?;
        Ok(())
    }

    fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: DBKey,
        V: DeserializeOwned,
    {
        match self.db().get(&key.as_db_key())? {
            Some(encoded) => {
                let value = bincode::deserialize(&encoded)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn delete<K>(&self, key: K) -> Result<()>
    where
        K: DBKey,
    {
        self.db().delete(&key.as_db_key())?;
        Ok(())
    }

    fn get_all<V>(&self, prefix: &[u8]) -> Result<Vec<V>>
    where
        V: DeserializeOwned,
    {
        let mut values = Vec::new();
        let iter = self.db().prefix_iterator(prefix);
        for item in iter {
            let (_key, value) = item?;
            let value = bincode::deserialize(&value)?;
            values.push(value);
        }
        Ok(values)
    }

    /// Check if a key exists
    fn contains_key<K>(&self, key: &K) -> Result<bool>
    where
        K: DBKey,
    {
        match self.db().get(&key.as_db_key()) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(anyhow!("Failed to check key existence: {}", e)),
        }
    }

    /// Flush database to disk
    fn flush(&self) -> Result<()> {
        self.db()
            .flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;
        debug!("🔄 [DATABASE] Flushed database to disk");
        Ok(())
    }



}

