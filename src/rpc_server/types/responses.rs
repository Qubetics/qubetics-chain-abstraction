use super::errors::ErrorResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionResponse {
	pub tx_hash: String,
	pub status: String,
	pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DepositIntentResponse {
	pub intent_id: String,
	pub status: String,
	pub message: String,
	pub raw_transaction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeStatusResponse {
	pub peer_id: String,
	pub connected_peers: usize,
	pub dkg_status: String,
	pub is_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeIdResponse {
	pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeartbeatResponse {
	pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UptimeResponse {
	pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserRegistrationResponse {
	pub status: String,
	pub message: String,
	pub derived_eth_address: Option<String>,
	pub derived_btc_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DKGStatusResponse {
	pub status: String,
	pub dkg_status: Option<String>,
	pub secret_share_available: bool,
	pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserMpcDepositVerifyResponse {
	pub status: String,
	pub signer_address: String,
	pub is_registered: bool,
	pub amount: u128,
	pub user_to_network_tx_id: Option<String>,
	pub network_to_target_tx_id: Option<String>,
	pub vault_to_network_tx_id: Option<String>,
	pub final_solver_id: Option<String>,
	pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SolverRewardResponse {
	pub status: String,
	pub solver_address: String,
	pub reward: Option<String>,
	pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetRewardSolverResponse {
	pub status: String,
	pub solver_address: String,
	pub reward_btc: Option<String>,
	pub reward_tics: Option<String>,
	pub message: String,
	pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserInfoResponse {
	pub status: String,
	pub user_id: Option<String>,
	pub ethereum_address: Option<String>,
	pub hmac_constant: Option<String>,
	pub has_tweaked_share: Option<bool>,
	pub has_user_group_key: Option<bool>,
	pub derived_eth_address: Option<String>,
	pub derived_btc_address: Option<String>,
	pub created_at: Option<String>,
	pub error: Option<ErrorResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnhancedUserRegistrationResponse {
	pub status: String,
	pub message: String,
	pub derived_eth_address: Option<String>,
	pub derived_btc_address: Option<String>,
	pub error: Option<ErrorResponse>,
}
