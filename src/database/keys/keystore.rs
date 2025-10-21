use crate::database::{constants::*, traits::DBKey};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerKeyPairKey {}
impl DBKey for PeerKeyPairKey {
	fn prefix(&self) -> &'static [u8] {
		PEER_KEYPAIR_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		vec![]
	}
}
