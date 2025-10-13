use crate::database::{constants::*, traits::DBKey};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserRegistrationKey {
	pub ethereum_address: String,
}
impl DBKey for UserRegistrationKey {
	fn prefix(&self) -> &'static [u8] {
		USER_REGISTRATION_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.ethereum_address.as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserIntentHashKey {
	pub ethereum_address: String,
	pub intent_hash: String,
}
impl DBKey for UserIntentHashKey {
	fn prefix(&self) -> &'static [u8] {
		USER_INTENT_HASH_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		format!("{}:{}", self.ethereum_address, self.intent_hash).as_bytes().to_vec()
	}
}
