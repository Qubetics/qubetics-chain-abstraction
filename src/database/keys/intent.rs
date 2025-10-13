use crate::database::{constants::*, traits::DBKey};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IntentRegistryKey {
	pub intent_hash: String,
}
impl DBKey for IntentRegistryKey {
	fn prefix(&self) -> &'static [u8] {
		INTENT_REGISTRY_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.intent_hash.as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IntentTransactionIdsKey {
	pub intent_hash: String,
}
impl DBKey for IntentTransactionIdsKey {
	fn prefix(&self) -> &'static [u8] {
		INTENT_TRANSACTION_IDS_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.intent_hash.as_bytes().to_vec()
	}
}
