

use crate::database::{
        db::Database,
        traits::KvStorage, PeerKeyPairKey,
    };
use anyhow::{anyhow, Result};
use rocksdb::DB;
use std::sync::Arc;
use tracing::debug;




#[derive(Clone)]
pub struct Keystorage {
	db: Database,
}

impl KvStorage for Keystorage {
    fn db(&self) -> &Arc<DB> {
        self.db.db()
    }
}

impl Keystorage {
	pub fn new(db: Database) -> Self {
		Self { db }
	}

	pub fn put_keypair(&self, keypair_bytes: &[u8]) -> Result<()> {
        let key = PeerKeyPairKey{};

		self.put(key.clone(), &keypair_bytes)
			.map_err(|e| anyhow!("Failed to store keypair: {}", e))?;
		debug!("🔑 [DATABASE] Stored keypair with key: {:?}", key);
		Ok(())
	}

	/// Get keypair bytes
	pub fn get_keypair(&self) -> Result<Option<Vec<u8>>> {
        let key = PeerKeyPairKey {};
		match self.get(key.clone()) {
			Ok(Some(bytes)) => {
				debug!("🔑 [DATABASE] Retrieved keypair with key: {:?}", key);
				Ok(Some(bytes))
			},
			Ok(None) => {
				debug!("🔑 [DATABASE] Keypair not found with key: {:?}", key);
				Ok(None)
			},
			Err(e) => Err(anyhow!("Failed to get keypair: {}", e)),
		}
	}

}





