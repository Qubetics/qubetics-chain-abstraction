use crate::database::{constants::*, traits::DBKey};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TransactionStatusKey {
	pub tx_hash: String,
}
impl DBKey for TransactionStatusKey {
	fn prefix(&self) -> &'static [u8] {
		TRANSACTION_STATUS_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.tx_hash.as_bytes().to_vec()
	}
}
