use crate::database::{constants::*, traits::DBKey};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKeyKey {
	pub node_id: String,
}
impl DBKey for PublicKeyKey {
	fn prefix(&self) -> &'static [u8] {
		PUBLIC_KEY_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.node_id.as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignatureKey {
	pub node_id: String,
}
impl DBKey for SignatureKey {
	fn prefix(&self) -> &'static [u8] {
		SIGNATURE_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.node_id.as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignatureRoundKey {
	pub round: u64,
	pub node_id: String,
}
impl DBKey for SignatureRoundKey {
	fn prefix(&self) -> &'static [u8] {
		SIGNATURE_ROUND_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		format!("{}:{}", self.round, self.node_id).as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AggregatedRoundKey {
	pub round: u64,
}
impl DBKey for AggregatedRoundKey {
	fn prefix(&self) -> &'static [u8] {
		AGGREGATED_ROUND_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.round.to_string().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FinalNodeRoundKey {
	pub round: u64,
}
impl DBKey for FinalNodeRoundKey {
	fn prefix(&self) -> &'static [u8] {
		FINAL_NODE_ROUND_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.round.to_string().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PendingTransactionKey {
	pub round: u64,
}
impl DBKey for PendingTransactionKey {
	fn prefix(&self) -> &'static [u8] {
		PENDING_TRANSACTION_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.round.to_string().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SolverAmountsKey {
	pub node_id: String,
	pub solver_id: String,
}
impl DBKey for SolverAmountsKey {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_AMOUNTS_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		format!("{}:{}", self.node_id, self.solver_id).as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AllSolverAmountsKey {
	pub node_id: String,
}
impl DBKey for AllSolverAmountsKey {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_AMOUNTS_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		format!("all:{}", self.node_id).as_bytes().to_vec()
	}
}
