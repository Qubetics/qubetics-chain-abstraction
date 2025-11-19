use crate::types::intent::DepositIntent;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub idempotency_key: Option<String>,
    pub started_at: Instant,
}

impl RequestContext {
    pub fn new(idempotency_key: Option<String>) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            idempotency_key,
            started_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub peer_id: String,
    pub connected_peers: usize,
    pub dkg_status: String,
    pub is_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdResponse {
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeResponse {
    pub uptime_seconds: u64,
}

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
pub struct UserRegistrationResponse {
    pub status: String,
    pub message: String,
    pub derived_eth_address: Option<String>,
    pub derived_btc_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGStatusResponse {
    pub status: String,
    pub dkg_status: Option<String>,
    pub secret_share_available: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverRewardRequest {
    pub signature: String,
    pub msg: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverRewardResponse {
    pub status: String,
    pub solver_address: String,
    pub reward: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRewardSolverRequest {
    pub solver_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRewardSolverResponse {
    pub status: String,
    pub solver_address: String,
    pub reward_btc: Option<String>,
    pub reward_tics: Option<String>,
    pub message: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRewardRequest {
    pub signature: String,
    pub message: String,
    pub ethereum_address: Option<String>,
    pub btc_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRewardResponse {
    pub status: String,
    pub ethereum_address: Option<String>,
    pub btc_address: Option<String>,
    pub reward_btc: Option<String>,
    pub reward_tics: Option<String>,
    pub total_reward: Option<String>,
    pub message: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub error_code: String,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedUserRegistrationResponse {
    pub status: String,
    pub message: String,
    pub derived_eth_address: Option<String>,
    pub derived_btc_address: Option<String>,
    pub error: Option<ErrorResponse>,
}
