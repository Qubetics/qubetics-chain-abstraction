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

/// Query for unclaimed (pending/batched) solver rewards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSolverRewardsRequest {
    pub solver_address: String,
}

/// One unclaimed reward entry (subset of PendingClaimRewardRequest; no message/signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnclaimedRewardEntry {
    pub request_id: String,
    pub status: String,
    pub tx_id: Option<String>,
    pub ethereum_address: Option<String>,
    pub btc_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSolverRewardsResponse {
    pub status: String,
    pub solver_address: String,
    /// On-chain unclaimed reward amounts from the SolverManager contract (BTC satoshis, TICS wei).
    pub reward_btc: Option<String>,
    pub reward_tics: Option<String>,
    pub unclaimed_rewards: Vec<UnclaimedRewardEntry>,
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

/// Internal representation of a queued withdraw-liquidity request.
/// Stored in RocksDB under keys with prefix "pending_withdraw_liquidity:".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingWithdrawRequest {
    pub request_id: String,
    pub solver_address: String,
    /// "TICS" or "BTC"
    pub asset: String,
    /// Amount as decimal string in smallest units for the asset chain
    pub amount: String,
    pub ethereum_address: Option<String>,
    pub btc_address: Option<String>,
    /// Original signed message payload from the HTTP request
    pub message: String,
    /// Optional on-chain batch transaction ID once processed
    pub tx_id: Option<String>,
    /// Logical status of this withdraw request: "Pending", "Batched", "Completed", "Failed", etc.
    pub status: String,
}

/// Internal representation of a queued claim-reward request.
/// Stored in RocksDB under keys with prefix "pending_claim_reward:".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingClaimRewardRequest {
    pub request_id: String,
    pub solver_address: String,
    pub ethereum_address: Option<String>,
    pub btc_address: Option<String>,
    /// Original signed message payload from the HTTP request
    pub message: String,
    pub signature: String,
    /// Optional BTC transaction ID once the claim-reward BTC batch is broadcast (stored on tx-id broadcast; do not mark done).
    #[serde(default)]
    pub tx_id: Option<String>,
    /// Logical status: "Pending", "Batched", "Completed", "Failed", etc.
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityRequest {
    /// Signature created by VERIFICATION_ADDRESS over the raw `message` bytes.
    pub signature: String,
    /// Opaque payload string that was signed. Expected to be a JSON string containing:
    /// { "solverId": string, "solverAddress": string, "amount": string, "chainId": number }.
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityResponse {
    pub status: String,
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

/// Response for GET /intents_solved_count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentsSolvedCountResponse {
    pub count: u64,
}
