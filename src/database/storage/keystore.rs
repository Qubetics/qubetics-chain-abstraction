use crate::{
	database::{db::Database, traits::Storage, PeerKeyPairKey, PEER_KEYPAIR_PREFIX},
	define_storage_adapter,
};
use anyhow::{anyhow, Result};
use tracing::debug;

define_storage_adapter!(PeerKeyPairAdapter, PeerKeyPairKey, Vec<u8>, PEER_KEYPAIR_PREFIX);

pub type PeerKeyPairStorage = Storage<PeerKeyPairAdapter>;

#[derive(Clone)]
pub struct Keystorage {
	keypairs: PeerKeyPairStorage,
}

impl Keystorage {
	pub fn new(db: Database) -> Self {
		Self { keypairs: PeerKeyPairStorage::new(db) }
	}

	pub fn put_keypair(&self, keypair_bytes: &[u8]) -> Result<()> {
		let key = PeerKeyPairKey {};

		self.keypairs
			.put(key.clone(), &keypair_bytes.to_vec())
			.map_err(|e| anyhow!("Failed to store keypair: {}", e))?;
		debug!("🔑 [DATABASE] Stored keypair with key: {:?}", key);
		Ok(())
	}

	/// Get keypair bytes
	pub fn get_keypair(&self) -> Result<Option<Vec<u8>>> {
		let key = PeerKeyPairKey {};
		match self.keypairs.get(key.clone()) {
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
