use anyhow::{anyhow, Result};
use rocksdb::DB;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
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

use std::marker::PhantomData;

use crate::Database;

pub trait StorageAdapter {
	type Key: DBKey;
	type Value: Serialize + DeserializeOwned;
	const PREFIX: &'static [u8];
}

#[derive(Clone)]
pub struct Storage<T: StorageAdapter> {
	db: Database,
	_marker: PhantomData<T>,
}

impl<T: StorageAdapter> Storage<T> {
	pub fn new(db: Database) -> Self {
		Self { db, _marker: PhantomData }
	}

	pub fn put(&self, key: T::Key, value: &T::Value) -> Result<()> {
		self.db.db().put(key.as_db_key(), bincode::serialize(value)?)?;
		Ok(())
	}

	pub fn get(&self, key: T::Key) -> Result<Option<T::Value>> {
		match self.db.db().get(key.as_db_key())? {
			Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
			None => Ok(None),
		}
	}

	pub fn delete(&self, key: T::Key) -> Result<()> {
		self.db.db().delete(key.as_db_key())?;
		Ok(())
	}

	pub fn get_all(&self) -> anyhow::Result<std::collections::HashMap<Vec<u8>, T::Value>> {
		let mut map = std::collections::HashMap::new();
		let iter = self.db.db().prefix_iterator(T::PREFIX);
		for item in iter {
			let (key, value) = item?;
			if let Ok(deserialized_value) = bincode::deserialize(&value) {
				map.insert(key.to_vec(), deserialized_value);
			}
		}
		Ok(map)
	}

	pub fn contains_key(&self, key: &T::Key) -> Result<bool> {
		match self.db.db().get(key.as_db_key()) {
			Ok(Some(_)) => Ok(true),
			Ok(None) => Ok(false),
			Err(e) => Err(anyhow!("Failed to check key existence: {}", e)),
		}
	}

	pub fn flush(&self) -> Result<()> {
		self.db.db().flush().map_err(|e| anyhow!("Failed to flush database: {}", e))?;
		debug!("🔄 [DATABASE] Flushed database to disk");
		Ok(())
	}
}
