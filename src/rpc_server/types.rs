use serde::{Deserialize, Serialize};

// Define the transaction types for the RPC server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyTransaction {
    pub to: String,
    pub value: String,
    pub nonce: u64,
    #[serde(rename = "gasLimit")]
    pub gas_limit: u64,
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTransaction {
    pub to: String,
    pub value: String,
    pub nonce: u64,
    #[serde(rename = "gasLimit")]
    pub gas_limit: u64,
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,

    /// ABI-encoded calldata as 0x-prefixed hex. Use "0x" when empty.
    #[serde(default)]
    pub data: String,
}

// Define the deposit intent structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositIntent {
    pub source_address: String,
    pub target_address: String,
    pub source_chain: String,
    pub target_chain: String,
    pub amount: u128,
    pub source_token: String,
    pub target_token: String,
    pub timestamp: u128, // Unix timestamp in seconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub tx_hash: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositIntentResponse {
    pub intent_id: String,
    pub status: String,
    pub message: String,
    pub raw_transaction: Option<String>,
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
    // Optional transaction ID and status for updating existing deposits
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

// Enhanced error types for better error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub error_code: String,
    pub message: String,
    pub details: Option<String>,
}

// User info response with proper error handling
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

// Enhanced user registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedUserRegistrationResponse {
    pub status: String,
    pub message: String,
    pub derived_eth_address: Option<String>,
    pub derived_btc_address: Option<String>,
    pub error: Option<ErrorResponse>,
}
