use serde::{Deserialize, Serialize};

use crate::rpc_server::types::common::DepositIntent;



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistrationRequest {
	pub ethereum_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMpcDepositRequest {
	pub signature: Option<String>,
	pub msg: DepositIntent,
	pub tx_id: Option<String>,
	pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverRewardRequest {
	pub signature: String,
	pub msg: String,
	pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRewardSolverRequest {
	pub solver_address: String,
}

