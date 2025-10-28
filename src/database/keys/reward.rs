use crate::database::{constants::*, traits::DBKey};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TotalLiquidityTicsKey;

impl DBKey for TotalLiquidityTicsKey {
	fn prefix(&self) -> &'static [u8] {
		TOTAL_LIQUIDITY_TICS_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		Vec::new()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TotalLiquidityBtcKey;

impl DBKey for TotalLiquidityBtcKey {
	fn prefix(&self) -> &'static [u8] {
		TOTAL_LIQUIDITY_BTC_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		Vec::new()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SolverRewardKey {
	pub solver_address: String,
}

impl DBKey for SolverRewardKey {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_REWARD_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.solver_address.to_lowercase().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SolverRewardTicsKey {
	pub solver_address: String,
}

impl DBKey for SolverRewardTicsKey {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_REWARD_TICS_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.solver_address.to_lowercase().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SolverRewardBtcKey {
	pub solver_address: String,
}

impl DBKey for SolverRewardBtcKey {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_REWARD_BTC_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.solver_address.to_lowercase().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClaimedRequestAmountKey {
	pub solver_address: String,
}

impl DBKey for ClaimedRequestAmountKey {
	fn prefix(&self) -> &'static [u8] {
		CLAIMED_REQUEST_AMOUNT_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.solver_address.to_lowercase().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IntentRewardStatusKey {
	pub intent_hash: String,
}

impl DBKey for IntentRewardStatusKey {
	fn prefix(&self) -> &'static [u8] {
		INTENT_REWARD_STATUS_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.intent_hash.to_lowercase().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SolverTicsTxnHashesKey {
	pub solver_address: String,
}

impl DBKey for SolverTicsTxnHashesKey {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_TICS_TXN_HASHES_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.solver_address.to_lowercase().as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SolverBtcTxnHashesKey {
	pub solver_address: String,
}

impl DBKey for SolverBtcTxnHashesKey {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_BTC_TXN_HASHES_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.solver_address.to_lowercase().as_bytes().to_vec()
	}
}
