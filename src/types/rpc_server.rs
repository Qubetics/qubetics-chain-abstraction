use crate::types::intent::DepositIntent;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub started_at: Instant,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
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
    /// Signature of the registration message (required for security)
    pub signature: Option<String>,
    /// The message that was signed (should be in format: "register:{ethereum_address}:{timestamp}")
    pub message: Option<String>,
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
    /// Deposit amount as a decimal string (matches DepositIntent.amount)
    pub amount: String,
    pub user_to_network_tx_id: Option<String>,
    pub network_to_target_tx_id: Option<String>,
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
pub struct SolverLiquidityRequest {
    pub solver_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverLiquidityResponse {
    pub status: String,
    pub solver_address: String,
    pub liquidity_btc: Option<String>,
    pub liquidity_tics: Option<String>,
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
    pub tics_reward_tx_id: Option<String>,
    pub btc_reward_tx_id: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawLiquidityRequest {
    pub signature: String,
    pub message: String,
    pub ethereum_address: Option<String>,
    pub btc_address: Option<String>,
    pub amount_tics: Option<String>,
    pub amount_btc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawLiquidityResponse {
    pub status: String,
    pub solver_address: String,
    pub liquidity_btc: Option<String>,
    pub liquidity_tics: Option<String>,
    pub ethereum_address: Option<String>,
    pub btc_address: Option<String>,
    pub tics_withdraw_tx_id: Option<String>,
    pub btc_withdraw_tx_id: Option<String>,
    pub message: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityRequest {
    pub signature: String,
    pub message: String,
    pub solver_id: String,
    pub amount_tics: Option<String>,
    pub amount_btc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityResponse {
    pub status: String,
    pub solver_address: String,
    pub solver_id: String,
    pub amount_tics: Option<String>,
    pub amount_btc: Option<String>,
    pub message: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPartialPubkeysRequest {
    pub peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPartialPubkeysResponse {
    pub status: String,
    pub peer_id: String,
    pub network_share_pubkey: Option<String>,
    pub vault_share_pubkey: Option<String>,
    pub user_share_pubkeys: Vec<UserSharePubkeyInfo>,
    pub message: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSharePubkeyInfo {
    pub user_eth_address: String,
    pub share_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNetworkAddressesResponse {
    pub status: String,
    pub network_addresses: Option<AddressInfo>,
    pub liquidity_operator_addresses: Option<AddressInfo>,
    pub message: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    pub eth_address: String,
    pub btc_address: String,
}
