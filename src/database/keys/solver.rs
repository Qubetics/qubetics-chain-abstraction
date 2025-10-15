use crate::database::{constants::*, traits::DBKey};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SolverLiquidity {
	pub address: String,
}

impl DBKey for SolverLiquidity {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_LIQUIDITY_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		self.address.as_bytes().to_vec()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AllSolverLiquidityKey;

impl DBKey for AllSolverLiquidityKey {
	fn prefix(&self) -> &'static [u8] {
		SOLVER_LIQUIDITY_PREFIX
	}
	fn key_bytes(&self) -> Vec<u8> {
		Vec::new()
	}
}
