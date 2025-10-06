use crate::database::{DkgStorage, RewardStorage};
use crate::types::{rpc::RPCRequest, ChannelMessage};
use crate::user_registry::{
    checksum_from_any, to_checksum_address, DatabaseUserRegistry, TransactionStatus,
};
use serde_json::Value;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha3::Keccak256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;
use warp::Filter;
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use rust_decimal_macros::dec;
use std::str::FromStr;

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

#[derive(Debug)]
pub enum RpcError {
    // Input validation errors
    InvalidAddress(String),
    MissingFields(String),
    InvalidRequest(String),

    // Database/storage errors
    DatabaseError(String),
    UserNotFound(String),
    RegistrationFailed(String),

    // Network/system errors
    NetworkError(String),
    DkgNotReady(String),
    Timeout(String),

    // General errors
    InternalError(String),
    SerializationError(String),
}

impl RpcError {
    pub fn to_error_response(&self) -> ErrorResponse {
        match self {
            RpcError::InvalidAddress(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "INVALID_ADDRESS".to_string(),
                message: "Invalid Ethereum address format".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::MissingFields(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "MISSING_FIELDS".to_string(),
                message: "Required fields are missing".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::InvalidRequest(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "INVALID_REQUEST".to_string(),
                message: "Invalid request format".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::DatabaseError(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "DATABASE_ERROR".to_string(),
                message: "Database operation failed".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::UserNotFound(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "USER_NOT_FOUND".to_string(),
                message: "User not found".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::RegistrationFailed(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "REGISTRATION_FAILED".to_string(),
                message: "User registration failed".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::NetworkError(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "NETWORK_ERROR".to_string(),
                message: "Network operation failed".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::DkgNotReady(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "DKG_NOT_READY".to_string(),
                message: "DKG is not ready".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::Timeout(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "TIMEOUT".to_string(),
                message: "Operation timed out".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::InternalError(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "INTERNAL_ERROR".to_string(),
                message: "Internal server error".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::SerializationError(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "SERIALIZATION_ERROR".to_string(),
                message: "Data serialization failed".to_string(),
                details: Some(msg.clone()),
            },
        }
    }
}

impl warp::reject::Reject for RpcError {}

// Input validation helper
fn validate_ethereum_address(address: &str) -> Result<String, RpcError> {
    if address.trim().is_empty() {
        return Err(RpcError::InvalidAddress(
            "Address cannot be empty".to_string(),
        ));
    }

    if !address.starts_with("0x") && address.len() != 42 {
        return Err(RpcError::InvalidAddress(
            "Address must be 42 characters and start with 0x".to_string(),
        ));
    }

    match checksum_from_any(address) {
        Ok(normalized) => Ok(normalized),
        Err(e) => Err(RpcError::InvalidAddress(format!(
            "Invalid address format: {}",
            e
        ))),
    }
}


// gRPC service definition
#[derive(Default)]
pub struct MpcRpcService {
    message_tx: Option<mpsc::Sender<ChannelMessage>>,
    user_registry: Option<DatabaseUserRegistry>,
}

impl MpcRpcService {
    pub fn new(message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            message_tx: Some(message_tx),
            user_registry: None,
        }
    }

    pub fn with_user_registry(mut self, user_registry: DatabaseUserRegistry) -> Self {
        self.user_registry = Some(user_registry);
        self
    }

    pub fn get_message_tx(&self) -> Option<mpsc::Sender<ChannelMessage>> {
        self.message_tx.clone()
    }

    pub fn get_user_registry(&self) -> Option<&DatabaseUserRegistry> {
        self.user_registry.as_ref()
    }
}

// Note: gRPC service implementation removed for now
// Focus on HTTP server implementation

// HTTP server implementation using warp
pub async fn start_http_server(
    message_tx: mpsc::Sender<ChannelMessage>,
    port: u16,
    user_registry: Arc<DatabaseUserRegistry>,
    dkg_storage: DkgStorage,
    reward_storage: RewardStorage,
    node_id: String,
    start_time: Instant,
) -> Result<(), warp::Rejection> {
    info!(
        "🔗 [RPC_SERVER] Received user registry - Arc pointer: {:p}",
        Arc::as_ptr(&user_registry)
    );

    let message_tx = std::sync::Arc::new(tokio::sync::Mutex::new(message_tx));
    // user_registry is already Arc<DatabaseUserRegistry>, no need to wrap again
    let dkg_storage = std::sync::Arc::new(dkg_storage);
    let reward_storage = std::sync::Arc::new(reward_storage);
    let start_time = std::sync::Arc::new(start_time);

    // POST /submit_transaction
    let submit_tx = warp::path("submit_transaction")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_submit_transaction);

    // POST /deposit_intent
    // let deposit_intent = warp::path("deposit_intent")
    //     .and(warp::post())
    //     .and(warp::body::json())
    //     .and(with_message_tx(message_tx.clone()))
    //     .and_then(handle_deposit_intent_wrapper);

    // POST /register_user
    let register_user = warp::path("register_user")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_user_registry(user_registry.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and(with_node_id(node_id.clone()))
        .and_then(handle_register_user);

    // POST /user_mpc_deposit
    let user_mpc_deposit = warp::path("user_mpc_deposit")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_user_registry(user_registry.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and_then(handle_user_mpc_deposit);

    // POST /solver_reward
    let solver_reward = warp::path("solver_reward")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_user_registry(user_registry.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_solver_reward);

    // POST /get_reward_solver
    let get_reward_solver = warp::path("get_reward_solver")
        .and(warp::get())
        .and(warp::query::<GetRewardSolverRequest>())
        .and(with_user_registry(user_registry.clone()))
        .and_then(handle_get_reward_solver);

    // GET /user_info/{ethereum_address}
    let get_user_info = warp::path("user_info")
        .and(warp::path::param())
        .and(warp::get())
        .and(with_user_registry(user_registry.clone()))
        .and_then(handle_get_user_info);

    // GET /node_id
    let get_node_id = warp::path("node_id")
        .and(warp::get())
        .and(with_node_id(node_id.clone()))
        .and_then(handle_get_node_id);

    // GET /status
    let get_status = warp::path("status")
        .and(warp::get())
        .and(with_message_tx(message_tx.clone()))
        .and_then(|message_tx| handle_get_status(message_tx));

    // GET /dkg_status
    let get_dkg_status = warp::path("dkg_status")
        .and(warp::get())
        .and(with_dkg_storage(dkg_storage.clone()))
        .and_then(handle_get_dkg_status);

    // GET /heartbeat
    let heartbeat = warp::path("heartbeat")
        .and(warp::get())
        .and_then(handle_heartbeat);

    // GET /uptime
    let uptime = warp::path("uptime")
        .and(warp::get())
        .and(with_start_time(start_time.clone()))
        .and_then(handle_get_uptime);

    // POST /start_dkg
    let start_dkg = warp::path("start_dkg")
        .and(warp::post())
        .and(with_message_tx(message_tx))
        .and_then(|message_tx| handle_start_dkg(message_tx));

    let routes = submit_tx
        .or(register_user)
        .or(get_user_info)
        .or(get_node_id)
        .or(get_status)
        .or(get_dkg_status)
        .or(start_dkg)
        .or(user_mpc_deposit)
        .or(solver_reward)
        .or(get_reward_solver)
        .or(heartbeat)
        .or(uptime);

    info!("🌐 Starting HTTP RPC server on port {}", port);
    // Enable CORS for all origins and common HTTP methods/headers
    let cors = warp::cors()
    .allow_credentials(true)
    .allow_headers(vec!["Content-Type", "Authorization"])
    .allow_methods(vec!["GET", "POST", "OPTIONS"])
    .allow_origin("http://localhost:3000")
    .allow_origin("http://localhost:3001")
    .allow_origin("http://127.0.0.1:3000")
    .allow_origin("http://127.0.0.1:3001")
    .allow_origin("https://dev-frontend.qubetics.work");

    warp::serve(routes.with(cors))
        .run(([0, 0, 0, 0], port))
        .await;
    Ok(())
}

fn with_message_tx(
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> impl Filter<
    Extract = (std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || message_tx.clone())
}

fn with_user_registry(
    user_registry: std::sync::Arc<DatabaseUserRegistry>,
) -> impl Filter<Extract = (std::sync::Arc<DatabaseUserRegistry>,), Error = std::convert::Infallible>
       + Clone {
    warp::any().map(move || user_registry.clone())
}

fn with_dkg_storage(
    dkg_storage: std::sync::Arc<DkgStorage>,
) -> impl Filter<Extract = (std::sync::Arc<DkgStorage>,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || dkg_storage.clone())
}

fn with_reward_storage(
    reward_storage: std::sync::Arc<RewardStorage>,
) -> impl Filter<Extract = (std::sync::Arc<RewardStorage>,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || reward_storage.clone())
}

fn with_node_id(
    node_id: String,
) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || node_id.clone())
}

fn with_start_time(
    start_time: std::sync::Arc<std::time::Instant>,
) -> impl Filter<Extract = (std::sync::Arc<std::time::Instant>,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || start_time.clone())
}

async fn handle_submit_transaction(
    tx: DummyTransaction,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📝 HTTP: Received transaction");

    let tx_hash = format!(
        "0x{:x}",
        sha2::Sha256::digest(format!("{:?}", tx).as_bytes())
    );

    // First, process the transaction locally (this node will sign it)
    info!("🔐 [LOCAL] Processing transaction locally for signing");

    // Send a special local processing message
    let local_msg = ChannelMessage::LocalTransaction {
        transaction: tx.clone(),
    };

    let tx_sender = message_tx.lock().await;
    if let Err(e) = tx_sender.send(local_msg).await {
        warn!("Failed to send transaction for local processing: {:?}", e);
        return Err(warp::reject::custom(TransactionError::NetworkError));
    }

    // Then broadcast to other nodes
    let gossipsub_msg = crate::types::GossipsubMessage::Transaction(tx.clone());
    let tx_data = serde_json::to_vec(&gossipsub_msg).map_err(|e| {
        warn!("Failed to serialize transaction: {}", e);
        warp::reject::custom(TransactionError::SerializationError)
    })?;

    if let Err(e) = tx_sender
        .send(ChannelMessage::Broadcast {
            topic: "transactions".to_string(),
            data: tx_data,
        })
        .await
    {
        warn!("Failed to send transaction to network: {:?}", e);
        return Err(warp::reject::custom(TransactionError::NetworkError));
    }

    info!("✅ HTTP: Transaction submitted to network");

    Ok(warp::reply::json(&TransactionResponse {
        tx_hash,
        status: "submitted".to_string(),
        message: "Transaction submitted to P_2_P network".to_string(),
    }))
}

// async fn handle_deposit_intent_wrapper(
//     request_json: serde_json::Value,
//     message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
// ) -> Result<impl warp::Reply, warp::Rejection> {
//     // Extract DepositIntent and user_eth_address from the JSON
//     let intent: DepositIntent = serde_json::from_value(request_json.clone())
//         .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?;

//     let user_eth_address: Option<String> = request_json.get("user_eth_address")
//         .and_then(|v| v.as_str())
//         .map(|s| s.to_string());

//     handle_deposit_intent(intent, user_eth_address, message_tx).await
// }
/// Convert source smallest units -> target smallest units using token prices (per whole units)



fn symbol_for(chain: &str) -> &'static str {
    match chain.to_lowercase().as_str() {
        "btc" | "bitcoin" => "BTC",
        _ => "TICS",
    }
}

fn decimals_for(chain: &str) -> u32 {
    match chain.to_lowercase().as_str() {
        "btc" | "bitcoin" => 8,     // satoshis
        "tics" | "qubetics" => 18,  // wei-like
        _ => 18,
    }
}

fn pow10_dec(n: u32) -> Decimal {
    // 10^n as Decimal without float errors
    let mut v = dec!(1);
    for _ in 0..n {
        v *= dec!(10);
    }
    v
}

fn convert_src_smallest_to_dst_smallest(
    amount_src_smallest: u128,
    src_chain: &str,
    dst_chain: &str,
    prices: &HashMap<String, Decimal>,
) -> Result<u128, TransactionError> {
    let src_sym = symbol_for(src_chain);
    let dst_sym = symbol_for(dst_chain);

    let p_src = *prices.get(src_sym).ok_or(TransactionError::PricingUnavailable)?;
    let p_dst = *prices.get(dst_sym).ok_or(TransactionError::PricingUnavailable)?;

    let src_dec = decimals_for(src_chain);
    let dst_dec = decimals_for(dst_chain);

    info!("🔄 [CONVERSION] Starting conversion:");
    info!("  📊 Source: {} {} (smallest units: {})", amount_src_smallest, src_sym, src_chain);
    info!("  📊 Target: {} (smallest units: {})", dst_sym, dst_chain);
    info!("  💰 Prices: {} = ${}, {} = ${}", src_sym, p_src, dst_sym, p_dst);
    info!("  🔢 Decimals: {} = {}, {} = {}", src_sym, src_dec, dst_sym, dst_dec);

    // Apply chain-specific multiplier before price conversion
    let adjusted_amount = match src_chain.to_lowercase().as_str() {
        "tics" | "qubetics" => {
            // For TICS source chain: divide by 10^10
            let divisor = pow10_dec(10);
            let result = Decimal::from_u128(amount_src_smallest)
                .ok_or(TransactionError::Overflow)?
                / divisor;
            info!("  🔄 TICS conversion: {} / 10^10 = {}", amount_src_smallest, result);
            result
        }
        "btc" | "bitcoin" => {
            // For BTC source chain: multiply by 10^10
            let multiplier = pow10_dec(10);
            let result = Decimal::from_u128(amount_src_smallest)
                .ok_or(TransactionError::Overflow)?
                * multiplier;
            info!("  🔄 BTC conversion: {} * 10^10 = {}", amount_src_smallest, result);
            result
        }
        _ => {
            // For other chains: no multiplier
            let result = Decimal::from_u128(amount_src_smallest)
                .ok_or(TransactionError::Overflow)?;
            info!("  🔄 Other chain conversion: {} (no multiplier)", amount_src_smallest);
            result
        }
    };

    // Convert to whole units using actual decimals
    let src_whole = adjusted_amount ;
    info!("  📏 Converted to whole units: {} / 10^{} = {}", adjusted_amount, src_dec, src_whole);

    // Apply price conversion
    let dst_whole = src_whole * p_src / p_dst;
    info!("  💱 Price conversion: {} * {} / {} = {}", src_whole, p_src, p_dst, dst_whole);

    // Convert back to smallest units
    let dst_smallest = dst_whole.floor();
    let result: u128 = dst_smallest.to_u128().ok_or(TransactionError::Overflow)?;
    
    info!("  📏 Converted to target smallest units: {} * 10^{} = {} (floored)", dst_whole, dst_dec, result);
    info!("  ✅ Final result: {} {} smallest units", result, dst_sym);

    Ok(result)
}

pub async fn handle_deposit_intent(
    intent: DepositIntent,
    user_eth_address: Option<String>,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
    transaction_type: crate::types::TransactionType,
    dkg_storage: std::sync::Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📝 HTTP: Received deposit intent request");
    if let Some(addr) = &user_eth_address {
        info!("📝 HTTP: User eth address provided for signing");
    }
    let mut required_amount_u128 = 0;

    // Only do price conversion for NetworkToTarget, else just use intent.amount
    if matches!(
        transaction_type,
        crate::types::TransactionType::NetworkToTarget
    ) {
        // Fetch current prices for BTC and TICS to determine the
        // value equivalence between source and target chains.
        let prices = fetch_crypto_prices()
            .await
            .map_err(|_| warp::reject::custom(TransactionError::NetworkError))?;

        // Helper closure to map chain names to the price symbols returned by
        // the price API. Any non-Bitcoin chain is treated as TICS (our EVM token).
        let chain_to_symbol = |chain: &str| match chain.to_lowercase().as_str() {
            "btc" | "bitcoin" => "BTC",
            _ => "TICS",
        };

        let source_symbol = chain_to_symbol(&intent.source_chain);
        let target_symbol = chain_to_symbol(&intent.target_chain);

        let source_price = *prices
            .get(source_symbol)
            .ok_or_else(|| warp::reject::custom(TransactionError::NetworkError))?;
        let target_price = *prices
            .get(target_symbol)
            .ok_or_else(|| warp::reject::custom(TransactionError::NetworkError))?;

        info!("💱 Conversion: computed source->target equivalence using current prices");

        // Convert the intent amount using the price ratio so we can compare
        // against the balance of the address on the chain we are about to
        // spend from.
        let target_smallest = convert_src_smallest_to_dst_smallest(
            intent.amount,
            &intent.source_chain,
            &intent.target_chain,
            &prices,
        )?;

        required_amount_u128 = target_smallest;

        info!("💱 Conversion: source amount converted to target smallest units");
    } else {
        // For VaultToNetwork and other types, use the intent amount plus 10%
        let base_amount = intent.amount + (intent.amount / 10);
        required_amount_u128 = base_amount;
        info!("💱 No price conversion needed; using adjusted intent amount");
    }

    // Additional balance validation for NetworkToTarget and VaultToNetwork
    // if matches!(
    //     transaction_type,
    //     crate::types::TransactionType::NetworkToTarget
    //         | crate::types::TransactionType::VaultToNetwork
    // ) {
    //     // Determine which chain to check based on the transaction type
    //     let chain_to_use = match transaction_type {
    //         crate::types::TransactionType::NetworkToTarget => intent.target_chain.to_lowercase(),
    //         crate::types::TransactionType::VaultToNetwork => intent.source_chain.to_lowercase(),
    //         _ => unreachable!(),
    //     };

        // Decide which address to check: network address or vault address
        // let (address_to_check, blockchain) =
        //     if crate::utils::transaction::is_evm_chain(&chain_to_use) {
        //         let address = match transaction_type {
        //             crate::types::TransactionType::NetworkToTarget => {
        //                 let group_key = dkg_storage
        //                     .get_final_public()
        //                     .await
        //                     .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?
        //                     .ok_or_else(|| {
        //                         warp::reject::custom(TransactionError::InvalidRequest)
        //                     })?;
        //                 let mut addr = crate::utils::get_eth_address_from_group_key(group_key);
        //                 if !addr.starts_with("0x") {
        //                     addr = format!("0x{}", addr);
        //                 }
        //                 addr
        //             }
        //             crate::types::TransactionType::VaultToNetwork => {
        //                 let (vault_eth, _) = dkg_storage
        //                     .get_vault_addresses()
        //                     .await
        //                     .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?
        //                     .ok_or_else(|| {
        //                         warp::reject::custom(TransactionError::InvalidRequest)
        //                     })?;
        //                 vault_eth
        //             }
        //             _ => unreachable!(),
        //         };
        //         (address, "eth".to_string())
        //     } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
        //         let address = match transaction_type {
        //             crate::types::TransactionType::NetworkToTarget => {
        //                 let group_key = dkg_storage
        //                     .get_final_public()
        //                     .await
        //                     .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?
        //                     .ok_or_else(|| {
        //                         warp::reject::custom(TransactionError::InvalidRequest)
        //                     })?;
        //                 crate::utils::get_btc_address_from_group_key(group_key)
        //             }
        //             crate::types::TransactionType::VaultToNetwork => {
        //                 let (_, vault_btc) = dkg_storage
        //                     .get_vault_addresses()
        //                     .await
        //                     .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?
        //                     .ok_or_else(|| {
        //                         warp::reject::custom(TransactionError::InvalidRequest)
        //                     })?;
        //                 vault_btc
        //             }
        //             _ => unreachable!(),
        //         };
        //         (address, "btc".to_string())
        //     } else {
        //         warn!("Unsupported chain for balance validation: {}", chain_to_use);
        //         return Err(warp::reject::custom(TransactionError::InvalidRequest));
        //     };

        // let balance = fetch_balance(&address_to_check, &blockchain)
        //     .await
        //     .map_err(|_| warp::reject::custom(TransactionError::NetworkError))?;

        // info!(
        //     "💰 Balance check: address {} on chain {} has balance {} (required: {})",
        //     address_to_check, chain_to_use, balance, required_amount_u128
        // );

        // if balance < required_amount_u128 {
        //     warn!(
        //         "Insufficient balance for address {} on chain {}: required {}, found {}",
        //         address_to_check, chain_to_use, required_amount_u128, balance
        //     );
        //     return Err(warp::reject::custom(TransactionError::InvalidRequest));
        // }
    // }

    let intent_id = format!("intent-{}", Uuid::new_v4());
    let deposit_intent_msg = ChannelMessage::DepositIntent {
        intent: intent.clone(),
        intent_id: intent_id.clone(),
        user_eth_address: user_eth_address.clone(),
        transaction_type: transaction_type.clone(),
        amount: required_amount_u128,
    };

    let tx_sender = message_tx.lock().await;
    if let Err(e) = tx_sender.send(deposit_intent_msg).await {
        warn!("Failed to send deposit intent to network: {:?}", e);
        return Err(warp::reject::custom(TransactionError::NetworkError));
    }

    info!(
        "✅ HTTP: Deposit intent submitted to network: {}",
        intent_id
    );

    Ok(warp::reply::json(&DepositIntentResponse {
        intent_id,
        status: "submitted".to_string(),
        message: "Deposit intent submitted to P_2_P network".to_string(),
        raw_transaction: None,
    }))
}

async fn handle_register_user(
    request: UserRegistrationRequest,
    user_registry: std::sync::Arc<DatabaseUserRegistry>,
    dkg_storage: std::sync::Arc<DkgStorage>,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
    node_id: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "👤 HTTP: Received user registration request for address: {}",
        request.ethereum_address
    );

    // Input validation
    let addr_cs = match validate_ethereum_address(&request.ethereum_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!(
                "❌ HTTP: Address validation failed for '{}': {:?}",
                request.ethereum_address, e
            );
            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "Invalid Ethereum address".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(e.to_error_response()),
            };
            return Ok(warp::reply::json(&error_response));
        }
    };

    // Check if user is already registered
    if let Some(_existing_user) = user_registry.get_user_by_address(&addr_cs).await {
        info!("⚠️ HTTP: User already registered: {}", addr_cs);
        let error_response = EnhancedUserRegistrationResponse {
            status: "error".to_string(),
            message: "User is already registered".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest("User is already registered".to_string())
                    .to_error_response(),
            ),
        };
        return Ok(warp::reply::json(&error_response));
    }

    // Check DKG status
    let dkg_secret_share = get_actual_dkg_secret_share(dkg_storage).await;
    if dkg_secret_share.is_none() {
        warn!("⚠️ HTTP: DKG not ready for user registration");
        let error_response = EnhancedUserRegistrationResponse {
            status: "error".to_string(),
            message: "DKG system is not ready. Please try again later.".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::DkgNotReady("DKG secret share not available".to_string())
                    .to_error_response(),
            ),
        };
        return Ok(warp::reply::json(&error_response));
    }

    // Attempt user registration
    match user_registry
        .register_user(&addr_cs, dkg_secret_share.as_ref(), &node_id)
        .await
    {
        Ok(registration) => {
            info!(
                "✅ HTTP: User registration successful for address: {}",
                addr_cs
            );

            // Log tweaked secret share status
            if registration.tweaked_secret_share.is_some() {
                info!(
                    "🔑 HTTP: Computed and stored tweaked secret share for user: {}",
                    addr_cs
                );
            } else {
                warn!(
                    "⚠️ HTTP: No tweaked secret share computed for user: {}",
                    addr_cs
                );
            }

            // Broadcast to other nodes via P2P network
            let user_reg_msg = ChannelMessage::UserRegistration {
                ethereum_address: addr_cs.clone(),
                node_id: node_id.to_string(),
            };

            // Send via message channel to be picked up by network layer
            if let Ok(tx) = message_tx.try_lock() {
                if let Err(e) = tx.send(user_reg_msg).await {
                    error!(
                        "❌ Failed to send user registration message to network: {}",
                        e
                    );
                    // Don't fail registration if broadcasting fails
                    warn!("⚠️ User registered locally but network broadcast failed");
                } else {
                    info!("📡 User registration message sent to network layer for broadcasting");
                }
            } else {
                warn!("⚠️ Could not acquire message channel lock for network broadcast");
            }

            // Wait for derived addresses to be populated
            info!("⏳ Waiting for derived addresses to be populated...");
            let mut attempts = 0;
            const MAX_ATTEMPTS: u8 = 10; // Wait up to 10 seconds

            let mut final_registration = registration.clone();
            while attempts < MAX_ATTEMPTS {
                // Check if derived addresses are now available
                match user_registry.get_user_by_address(&addr_cs).await {
                    Some(updated_user) => {
                        if updated_user.derived_eth_address.is_some()
                            && updated_user.derived_btc_address.is_some()
                        {
                            final_registration = updated_user;
                            info!("✅ Derived addresses are now available!");
                            break;
                        }
                    }
                    None => {
                        error!("❌ User disappeared from registry during address derivation");
                        break;
                    }
                }

                attempts += 1;
                if attempts < MAX_ATTEMPTS {
                    info!(
                        "⏳ Attempt {}/{}: Derived addresses not ready yet, waiting 1 second...",
                        attempts, MAX_ATTEMPTS
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }

            if attempts >= MAX_ATTEMPTS {
                warn!(
                    "⚠️ Derived addresses not available after {} attempts",
                    MAX_ATTEMPTS
                );
            }

            // Log derived addresses if available
            if let Some(eth_addr) = &final_registration.derived_eth_address {
                info!("📬 HTTP: Derived ETH address stored for {}", addr_cs);
            }
            if let Some(btc_addr) = &final_registration.derived_btc_address {
                info!("📬 HTTP: Derived BTC address stored for {}", addr_cs);
            }

            // Successful response
            let response = EnhancedUserRegistrationResponse {
                status: "success".to_string(),
                message: "User registered successfully".to_string(),
                derived_eth_address: final_registration.derived_eth_address,
                derived_btc_address: final_registration.derived_btc_address,
                error: None,
            };

            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            error!(
                "❌ HTTP: User registration failed for address {}: {}",
                addr_cs, e
            );

            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "User registration failed".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(RpcError::RegistrationFailed(e.to_string()).to_error_response()),
            };

            Ok(warp::reply::json(&error_response))
        }
    }
}

// Helper function to get transaction ID from intent hash
async fn get_transaction_id_for_intent(
    user_registry: &DatabaseUserRegistry,
    intent_hash: &[u8],
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let intent_hash_hex = hex::encode(intent_hash);

    // Fetch any recorded transaction IDs for this intent hash
    if let Some(tx_ids) = user_registry
        .get_intent_transaction_ids(&intent_hash_hex)
        .await
    {
        // Check each candidate transaction id individually
        let mut user_to_network_tx_id = None;
        if let Some(ref tx_id) = tx_ids.user_to_network_tx_id {
            if user_registry.get_transaction_status(tx_id).await.is_some() {
                user_to_network_tx_id = Some(tx_id.clone());
            }
        }

        let mut network_to_target_tx_id = None;
        if let Some(ref tx_id) = tx_ids.network_to_target_tx_id {
            if user_registry.get_transaction_status(tx_id).await.is_some() {
                network_to_target_tx_id = Some(tx_id.clone());
            }
        }

        let mut vault_to_network_tx_id = None;
        if let Some(ref tx_id) = tx_ids.vault_to_network_tx_id {
            if user_registry.get_transaction_status(tx_id).await.is_some() {
                vault_to_network_tx_id = Some(tx_id.clone());
            }
        }
        let final_solver_id = tx_ids.final_solver_id.clone();
        return (
            user_to_network_tx_id,
            network_to_target_tx_id,
            vault_to_network_tx_id,
            final_solver_id,
        );
    }

    (None, None, None, None)
}

/// Wait for a transaction ID or chain error associated with the given intent hash.
/// Polls the database frequently to return as soon as possible and times out
/// after the provided number of seconds. Tries to get all transaction IDs when possible,
/// but returns with whatever is available after the timeout.
async fn wait_for_transaction_result(
    user_registry: &DatabaseUserRegistry,
    intent_hash: &[u8],
    timeout_secs: u64,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let start = std::time::Instant::now();
    let intent_hash_hex = hex::encode(intent_hash);
    let poll_interval = tokio::time::Duration::from_millis(250);
    let timeout = tokio::time::Duration::from_secs(timeout_secs);

    // Give a bit more time to potentially get all transaction IDs
    let extended_timeout = timeout + tokio::time::Duration::from_secs(2);
    let mut best_result = (None, None, None, None, None);

    loop {
        // Check for transaction ids
        let (u2n_tx, n2t_tx, v2n_tx, final_solver) =
            get_transaction_id_for_intent(user_registry, intent_hash).await;

        // Update our best result if we have new information
        if u2n_tx.is_some() || n2t_tx.is_some() || v2n_tx.is_some() {
            best_result = (u2n_tx, n2t_tx, v2n_tx, final_solver, None);
            // If we have all transaction IDs, return immediately
            if best_result.0.is_some()
                && best_result.1.is_some()
                && best_result.2.is_some()
            {
                return best_result;
            }

            // If we have at least one, continue polling for a bit longer to see if we can get the others
            // But don't wait too long - return after the original timeout if we have at least one
            if start.elapsed() >= timeout {
                return best_result;
        }
        }

        // Check for any recorded chain error
        if let Some(tx_ids) = user_registry
            .get_intent_transaction_ids(&intent_hash_hex)
            .await
        {
            if let Some(error_msg) = tx_ids.error_message {
                return (
                    None,
                    None,
                    None,
                    tx_ids.final_solver_id.clone(),
                    Some(error_msg),
                );
            }
        }

        // If we've exceeded the extended timeout, return whatever we have
        if start.elapsed() >= extended_timeout {
            break;
        }

        tokio::time::sleep(poll_interval).await;
    }

    // Return the best result we found, or None if we found nothing
    best_result
}

pub async fn fetch_crypto_prices() -> Result<HashMap<String, Decimal>, String> {
    use tracing::{debug, error, info};

    let base_url = std::env::var("BACKEND_API_URL")
        .unwrap_or_else(|_| "http://172.16.15.63:7322".to_string());
    let url = format!("{}/api/v1/cryptos/prices?symbols=BTC,TICS", base_url);
    let client = reqwest::Client::new();

    info!("Fetching crypto prices from URL: {}", url);

    let resp = client.get(&url).send().await.map_err(|e| {
        error!("Failed to fetch crypto prices: {}", e);
        format!("Failed to fetch crypto prices: {}", e)
    })?;

    let status = resp.status();
    debug!("Crypto prices API response status: {}", status);

    let resp_text = resp.text().await.map_err(|e| {
        error!("Failed to read crypto prices response text: {}", e);
        format!("Failed to read crypto prices response text: {}", e)
    })?;

    debug!("Crypto prices API response body: {}", resp_text);

    if !status.is_success() {
        error!(
            "Crypto prices API returned non-success status {}: {}",
            status, resp_text
        );
        return Err(format!(
            "Crypto prices API returned non-success status {}: {}",
            status, resp_text
        ));
    }

    let resp_json: Value = serde_json::from_str(&resp_text).map_err(|e| {
        error!("Failed to parse crypto prices response: {}", e);
        format!("Failed to parse crypto prices response: {}", e)
    })?;

    debug!("Crypto prices API response JSON: {:?}", resp_json);

    if resp_json.get("error").and_then(|v| v.as_bool()) == Some(true) {
        let msg = resp_json
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        error!("Crypto prices API error: {}", msg);
        return Err(format!("Crypto prices API error: {}", msg));
    }

    let data = resp_json.get("data").ok_or_else(|| {
        error!("No 'data' field in crypto prices response");
        "No 'data' field in crypto prices response".to_string()
    })?;

    let mut prices: HashMap<String, Decimal> = HashMap::new();

    // Tolerant parsing: accept string or number for price fields
    let to_decimal = |v: &Value| -> Option<Decimal> {
        match v {
            Value::String(s) => Decimal::from_str(s).ok(),
            Value::Number(n) => Decimal::from_str(&n.to_string()).ok(),
            _ => None,
        }
    };

    if let Some(obj) = data.as_object() {
        for (symbol, value) in obj {
            if let Some(price) = to_decimal(value) {
                debug!("Parsed Decimal price for {}: {}", symbol, price);
                prices.insert(symbol.clone(), price);
            } else {
                // Last-ditch: log and skip
                debug!("Could not parse Decimal price for {}: {:?}", symbol, value);
            }
        }
    } else {
        debug!("'data' field is not an object in crypto prices response");
    }

    info!("Fetched crypto prices (Decimal): {:?}", prices);
    Ok(prices)
}
// async fn fetch_balance(address: &str, blockchain: &str) -> Result<u128, String> {
//     info!(
//         "Fetching balance for address: {}, blockchain: {}",
//         address, blockchain
//     );
//     let base_url = std::env::var("BACKEND_API_URL")
//         .unwrap_or_else(|_| "http://172.16.15.63:7322".to_string());
//     let url = format!(
//         "{}/api/v1/balance/{}?blockchain={}",
//         base_url,
//         address, blockchain
//     );

//     let client = reqwest::Client::new();
//     let resp = client
//         .get(&url)
//         .send()
//         .await
//         .map_err(|e| format!("Failed to fetch balance: {}", e))?;

//     info!("Balance API response status: {}", resp.status());

//     let resp_text = resp
//         .text()
//         .await
//         .map_err(|e| format!("Failed to read balance response text: {}", e))?;

//     info!("Full balance API response body: {}", resp_text);

//     // Parse the response text as JSON
//     let resp_json: serde_json::Value = serde_json::from_str(&resp_text)
//         .map_err(|e| format!("Failed to parse balance response: {}", e))?;

//     info!("Balance API response JSON: {}", resp_json);

//     // Determine the multiplier based on blockchain type
//     let multiplier = match blockchain.to_lowercase().as_str() {
//         "eth" | "ethereum" | "qubetics" => 1e18,
//         "btc" | "bitcoin" => 1e8,
//         _ => 1e18, // Default to 1e18 if unknown
//     };

//     // The new API response has the balance under "data" as a float, so we fetch it and multiply by the correct multiplier
//     let balance_f64 = resp_json
//         .get("data")
//         .and_then(|v| v.as_f64())
//         .unwrap_or(0.0);
//     let balance_str = format!("{}", (balance_f64 * multiplier).round() as u128);

//     info!("Parsed balance string: {}", balance_str);

//     balance_str
//         .parse::<u128>()
//         .map_err(|e| format!("Failed to parse balance value: {}", e))
// }

/// Check whether a transaction is confirmed on a given chain using the
/// external transaction confirmation service.
///
/// Returns `Ok(true)` if the transaction is confirmed, `Ok(false)` if the
/// transaction is not yet confirmed, and `Err` if the API call fails or returns
/// an unexpected response.
// pub async fn check_tx_confirmation(chain: &str, tx_id: &str) -> anyhow::Result<bool> {
//     // Map common chain aliases to the API expected values
//     let chain_lc = chain.to_lowercase();
//     let api_chain: &str = match chain_lc.as_str() {
//         "btc" | "bitcoin" => "btc",
//         "qubetics" => "eth",
//         other => other,
//     };  

//     let base_url = std::env::var("BACKEND_API_URL")
//         .unwrap_or_else(|_| "http://172.16.15.63:7322".to_string());
//     let url = format!(
//         "{}/api/v1/tx-confirmation/{}/{}",
//         base_url,
//         api_chain, tx_id
//     );

//     let client = reqwest::Client::new();
//     let resp = client
//         .get(&url)
//         .send()
//         .await
//         .map_err(|e| anyhow::anyhow!("Failed to send tx confirmation request: {}", e))?;

//     if !resp.status().is_success() {
//         return Err(anyhow::anyhow!(
//             "Tx confirmation API error: {}",
//             resp.status()
//         ));
//     }

//     let json: serde_json::Value = resp
//         .json()
//         .await
//         .map_err(|e| anyhow::anyhow!("Failed to parse tx confirmation response: {}", e))?;

//     let status = json.get("data").and_then(|v| v.as_str()).ok_or_else(|| {
//         anyhow::anyhow!("Missing or invalid 'data' field in tx confirmation response")
//     })?;

//     Ok(status.eq_ignore_ascii_case("confirmed"))
// }

async fn handle_user_mpc_deposit(
    req: UserMpcDepositRequest,
    user_registry: std::sync::Arc<DatabaseUserRegistry>,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
    dkg_storage: std::sync::Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🧾 HTTP: user_mpc_deposit received");
    // If transaction ID and status are provided, update the database accordingly

    // Serialize the DepositIntent to match the client's JSON.stringify() format
    // Use compact JSON serialization (no spaces) to match JavaScript's JSON.stringify()
    let intent_json = serde_json::to_string(&req.msg).unwrap();
    let intent_bytes = intent_json.as_bytes();
    let intent_hash = Keccak256::digest(intent_bytes);
    let intent_hash_hex = hex::encode(intent_hash);

    let mut transaction_ids = Vec::new();

    let tx_mapping = user_registry
        .get_intent_transaction_ids(&intent_hash_hex)
        .await;
    if let Some(tx_ids) = user_registry
        .get_intent_transaction_ids(&intent_hash_hex)
        .await
    {
        // Only store transaction IDs if there's no error
        if tx_ids.error_message.is_none() {
            if let Some(ref user_to_network_tx) = tx_ids.user_to_network_tx_id {
                transaction_ids.push(user_to_network_tx.clone());
            }
            if let Some(ref network_to_target_tx) = tx_ids.network_to_target_tx_id {
                transaction_ids.push(network_to_target_tx.clone());
            }
        }
    }
    // Process the deposit intent
    // If there are any transaction IDs, req.tx_id must be provided, else return error
    // if transaction_ids.len() >= 1 && req.tx_id.is_none() {
    //     return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
    //         status: "error".to_string(),
    //         signer_address: "".to_string(),
    //         is_registered: false,
    //         amount: 0,
    //         user_to_network_tx_id: None,
    //         network_to_target_tx_id: None,
    //         vault_to_network_tx_id: None,
    //         error_message: Some(
    //             "Transaction ID must be provided when transaction(s) already exist for this intent"
    //                 .to_string(),
    //         ),
    //     }));
    // }

    let transaction_type = if transaction_ids.len() == 1 {
        crate::types::TransactionType::NetworkToTarget
    } else if transaction_ids.len() == 0 {
        crate::types::TransactionType::UserToVault
    } else {
        // More than 2 transactions indicates a duplicate intent
        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            signer_address: "".to_string(),
            is_registered: false,
            amount: 0,
            user_to_network_tx_id: tx_mapping
                .as_ref()
                .and_then(|tx| tx.user_to_network_tx_id.clone()),
            network_to_target_tx_id: tx_mapping
                .as_ref()
                .and_then(|tx| tx.network_to_target_tx_id.clone()),
            vault_to_network_tx_id: None,
            final_solver_id: None,
            error_message: Some("Duplicate intent detected - this intent has already been processed".to_string()),
        }));
    };

    // if let Some(ref tx_id) = req.tx_id {
    //     if let Some(status) = user_registry.get_transaction_status(tx_id).await {
    //         if status == TransactionStatus::Confirmed {
    //             warn!(
    //                 "❌ Transaction {} is already confirmed, rejecting duplicate call",
    //                 tx_id
    //             );
    //             return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
    //                 status: "error".to_string(),
    //                 signer_address: "".to_string(),
    //                 is_registered: false,
    //                 amount: 0,
    //                 user_to_network_tx_id: None,
    //                 network_to_target_tx_id: None,
    //                 vault_to_network_tx_id: None,
    //                 error_message: Some(format!(
    //                     "Transaction {} is already confirmed and cannot be processed again",
    //                     tx_id
    //                 )),
    //             }));
    //         }
    //     }
    // }

    info!(
        "🔐 Processing MPC deposit - Intent hash: {:?}, Amount: {}",
        intent_hash, req.msg.amount
    );
    info!("📝 Server JSON serialization prepared");
    info!(
        "📏 JSON length: {}, First 100 chars: {}",
        intent_json.len(),
        if intent_json.len() > 100 {
            &intent_json[0..100]
        } else {
            &intent_json
        }
    );
    // Check if the intent hash is already stored; if yes, retrieve user details in a variable
    // Retrieve the user by intent hash and immediately handle Some/None
    let user_registration = match user_registry
        .get_user_by_intent_hash(&intent_hash_hex)
        .await
    {
        Some(existing_user) => existing_user,
        None => {
            // No existing user for this intent hash
            match &req.signature {
                Some(signature) => {
                    info!("No existing user found for intent hash, but signature is present in the request.");
                    let (compact, v) = match normalize_eth_signature(signature) {
                        Ok(t) => t,
                        Err(e) => {
                            warn!("❌ Failed to normalize signature: {}", e);
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                signer_address: "".to_string(),
                                is_registered: false,
                                amount: 0,
                                user_to_network_tx_id: None,
                                network_to_target_tx_id: None,
                                vault_to_network_tx_id: None,
                                final_solver_id: None,
                                error_message: Some(format!("Invalid signature format: {}", e)),
                            }));
                        }
                    };
                    let (signer, _used_personal) = match recover_eth_address_secp(
                        intent_bytes,
                        &compact,
                        v,
                        true,
                    ) {
                        Ok(addr) => (addr, true),
                        Err(e1) => {
                            warn!("⚠️ personal_sign recovery failed: {}", e1);
                            match recover_eth_address_secp(intent_bytes, &compact, v, false) {
                                Ok(addr) => (addr, false),
                                Err(e2) => {
                                    error!(
                                        "❌ Both signature recovery methods failed: personal_sign={}, raw={}",
                                        e1, e2
                                    );
                                    return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                        status: "error".to_string(),
                                        signer_address: "".to_string(),
                                        is_registered: false,
                                        amount: 0,
                                        user_to_network_tx_id: None,
                                        network_to_target_tx_id: None,
                                        vault_to_network_tx_id: None,
                                        final_solver_id: None,
                                        error_message: Some(format!(
                                            "Failed to recover signature: personal_sign={}, raw={}",
                                            e1, e2
                                        )),
                                    }));
                                }
                            }
                        }
                    };
                    // Fetch UserRegistration from signer address first
                    let user_reg = match user_registry.get_user_by_address(&signer).await {
                        Some(user_reg) => user_reg,
                        None => {
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                signer_address: signer.clone(),
                                is_registered: false,
                                amount: 0,
                                user_to_network_tx_id: None,
                                network_to_target_tx_id: None,
                                vault_to_network_tx_id: None,
                                final_solver_id: None,
                                error_message: Some(
                                    "No user registration found for signer address.".to_string(),
                                ),
                            }));
                        }
                    };
                    // Fetch balance of derived address based on source_chain
                    // Add 10% buffer to the minimum required amount
                    let min_amount = req.msg.amount + (req.msg.amount / 10);
                    let source_chain = req.msg.source_chain.to_lowercase();
                    let mut address_to_check = String::new();
                    let mut blockchain = String::new();

                    if source_chain == "qubetics" {
                        // Use eth_derived address from user_reg details
                        if let Some(eth_addr) = &user_reg.derived_eth_address {
                            address_to_check = eth_addr.clone();
                            // Ensure 0x prefix
                            if !address_to_check.starts_with("0x") {
                                address_to_check = format!("0x{}", address_to_check);
                            }
                        } else {
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                signer_address: signer.clone(),
                                is_registered: true,
                                amount: 0,
                                user_to_network_tx_id: None,
                                network_to_target_tx_id: None,
                                vault_to_network_tx_id: None,
                                final_solver_id: None,
                                error_message: Some(
                                    "No eth_derived address found for user.".to_string(),
                                ),
                            }));
                        }
                        blockchain = "eth".to_string();
                    } else if source_chain == "bitcoin" {
                        // Use btc_derived address from user_reg details
                        if let Some(btc_addr) = &user_reg.derived_btc_address {
                            address_to_check = btc_addr.clone();
                        } else {
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                signer_address: signer.clone(),
                                is_registered: true,
                                amount: 0,
                                user_to_network_tx_id: None,
                                network_to_target_tx_id: None,
                                vault_to_network_tx_id: None,
                                final_solver_id: None,
                                error_message: Some(
                                    "No btc_derived address found for user.".to_string(),
                                ),
                            }));
                        }
                        blockchain = "btc".to_string();
                    } else {
                        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                            status: "error".to_string(),
                            signer_address: signer.clone(),
                            is_registered: true,
                            amount: 0,
                            user_to_network_tx_id: None,
                            network_to_target_tx_id: None,
                            vault_to_network_tx_id: None,
                            final_solver_id: None,
                            error_message: Some(format!(
                                "Unsupported source chain: {}",
                                source_chain
                            )),
                        }));
                    }
                    // let balance = match fetch_balance(&address_to_check, &blockchain).await {
                    //     Ok(b) => b,
                    //     Err(e) => {
                    //         return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                    //             status: "error".to_string(),
                    //             signer_address: signer.clone(),
                    //             is_registered: true,
                    //             amount: 0,
                    //             user_to_network_tx_id: None,
                    //             network_to_target_tx_id: None,
                    //             vault_to_network_tx_id: None,
                    //             error_message: Some(e),
                    //         }));
                    //     }
                    // };
                    // if balance < min_amount {
                    //     return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                    //         status: "error".to_string(),
                    //         signer_address: signer.clone(),
                    //         is_registered: true,
                    //         amount: balance,
                    //         user_to_network_tx_id: None,
                    //         network_to_target_tx_id: None,
                    //         vault_to_network_tx_id: None,
                    //         error_message: Some(format!(
                    //             "Insufficient balance: required {}, found {}",
                    //             min_amount, balance
                    //         )),
                    //     }));
                    // }
                    // Store intent hash via network channel and broadcast
                    let intent_hash_bytes = intent_hash.to_vec();
                    let store_msg = ChannelMessage::IntentHash {
                        intent_hash: intent_hash_bytes.clone(),
                        signer: signer.clone(),
                        intent: req.msg.clone(),
                    };
                    let tx_sender = message_tx.lock().await;
                    if let Err(e) = tx_sender.send(store_msg).await {
                        error!("❌ Failed to dispatch intent hash store message: {}", e);
                        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                            status: "error".to_string(),
                            signer_address: signer.clone(),
                            is_registered: true,
                            amount: 0,
                            user_to_network_tx_id: None,
                            network_to_target_tx_id: None,
                            vault_to_network_tx_id: None,
                            final_solver_id: None,
                            error_message: Some(format!("Failed to process deposit intent: {}", e)),
                        }));
                    }

                    info!("✅ Intent hash store message sent for user: {}", signer);

                    user_reg
                }
                None => {
                    // No signature provided and no details found in DB, return error
                    return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                        status: "error".to_string(),
                        signer_address: "".to_string(),
                        is_registered: false,
                        amount: 0,
                        user_to_network_tx_id: None,
                        network_to_target_tx_id: None,
                        vault_to_network_tx_id: None,
                        final_solver_id: None,
                        error_message: Some("No details found in database for intent hash and no signature provided.".to_string()),
                    }));
                }
            }
        }
    };

    let user_eth_address = match transaction_type {
        crate::types::TransactionType::UserToVault => Some(user_registration.ethereum_address.clone()),
        _ => None,
    };
    // Fetch all transaction IDs corresponding to this intent hash
    let intent_hash_hex = hex::encode(&intent_hash);

    let chain_to_check = if let Some(ref tx_id) = req.tx_id {
        if let Some(ref map) = tx_mapping {
            if map.user_to_network_tx_id.as_ref() == Some(tx_id) {
                Some("source")
            } else if map.network_to_target_tx_id.as_ref() == Some(tx_id) {
                Some("target")
            } else {
                Some("tics")
            }
        } else {
            None
        }
    } else {
        None
    };

    // Only perform this check if a tx_id is provided
    if let Some(ref tx_id) = req.tx_id {
        // Determine which chain to check based on mapping logic
        let source_chain = req.msg.source_chain.to_lowercase();
        let target_chain = req.msg.target_chain.to_lowercase();
        let selected_chain = match chain_to_check {
            Some("target") => &target_chain,
            Some("source") => &source_chain,
            // If chain_to_check is "tics" or any other value, always use "tics"
            Some("tics") | Some(_) => "tics",
            None => "tics", // Defensive, but should not happen if tx_id is Some
        };

        // match check_tx_confirmation(selected_chain, tx_id).await {
        //     Ok(true) => {
        //         // Only update the status in db if txn is confirmed
        //         if let Err(e) = user_registry
        //             .update_transaction_status(tx_id, TransactionStatus::Confirmed)
        //             .await
        //         {
        //             error!("Failed to update transaction status in db: {}", e);
        //         } else {
        //             info!(
        //                 "✅ Updated transaction status in db for {}: {:?}",
        //                 tx_id,
        //                 TransactionStatus::Confirmed
        //             );
        //         }
        //     }
        //     Ok(false) => {
        //         warn!(
        //             "Transaction {} not yet confirmed on chain {}",
        //             tx_id, selected_chain
        //         );

        //         return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
        //             status: "pending".to_string(),
        //             signer_address: user_registration.ethereum_address.clone(),
        //             is_registered: true,
        //             amount: req.msg.amount,
        //             user_to_network_tx_id: None,
        //             network_to_target_tx_id: None,
        //             vault_to_network_tx_id: None,
        //             error_message: Some("Transaction not yet confirmed on chain".to_string()),
        //         }));
        //     }
        //     Err(e) => {
        //         error!("Tx confirmation API returned error: {}", e);
        //         return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
        //             status: "error".to_string(),
        //             signer_address: user_registration.ethereum_address.clone(),
        //             is_registered: true,
        //             amount: req.msg.amount,
        //             user_to_network_tx_id: None,
        //             network_to_target_tx_id: None,
        //             vault_to_network_tx_id: None,
        //             error_message: Some(format!("Tx confirmation API error: {}", e)),
        //         }));
        //     }
        // }
        // If confirmed, continue processing
    }

    match handle_deposit_intent(
        req.msg.clone(),
        user_eth_address,
        message_tx,
        transaction_type,
        dkg_storage.clone(),
    )
    .await
    {
        Ok(_) => {
            info!(
                "✅ Deposit intent processed successfully for user: {}",
                user_registration.ethereum_address
            );
        }
        Err(e) => {
            error!("❌ Failed to process deposit intent: {:?}", e);

            // Just return the raw error message as it is
            let error_message = format!("{:?}", e);

            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                status: "error".to_string(),
                signer_address: user_registration.ethereum_address.clone(),
                is_registered: true,
                amount: req.msg.amount,
                user_to_network_tx_id: None,
                network_to_target_tx_id: None,
                vault_to_network_tx_id: None,
                final_solver_id: None,
                error_message: Some(error_message),
            }));
        }
    }

    // Wait for the actual transaction result (success with TX ID or chain error)
    let intent_hash_hex = hex::encode(&intent_hash);
    info!(
        "✅ Deposit intent submitted successfully. Intent hash: {}",
        intent_hash_hex
    );
    info!("⏳ Waiting for transaction to be processed by the network...");

    // Poll the database frequently for up to 10 seconds so that we can
    // return a response as soon as the transaction is available.
    let (u2n_tx_id, n2t_tx_id, v2n_tx_id, final_solver_id, chain_error) =
        wait_for_transaction_result(&user_registry, &intent_hash, 40).await;

    // Log the transaction IDs if recorded
    if let Some(ref tx_id_str) = u2n_tx_id {
        info!(
            "✅ User->Network transaction completed with ID: {:?}",
            tx_id_str
        );
    }
    if let Some(ref tx_id_str) = n2t_tx_id {
        info!(
            "✅ Network->Target transaction completed with ID: {:?}",
            tx_id_str
        );
    }
    if let Some(ref tx_id_str) = v2n_tx_id {
        info!(
            "✅ Vault->Network transaction completed with ID: {:?}",
            tx_id_str
        );
    }

    if u2n_tx_id.is_some() || n2t_tx_id.is_some() || v2n_tx_id.is_some() {
        // At least one transaction succeeded
        Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "success".to_string(),
            signer_address: user_registration.ethereum_address.clone(),
            is_registered: true,
            amount: req.msg.amount,
            user_to_network_tx_id: u2n_tx_id,
            network_to_target_tx_id: n2t_tx_id,
            vault_to_network_tx_id: v2n_tx_id,
            final_solver_id: final_solver_id.clone(),
            error_message: None,
        }))
    } else if let Some(error_msg) = chain_error {
        // Chain error occurred - return the actual error from blockchain
        Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            signer_address: user_registration.ethereum_address.clone(),
            is_registered: true,
            amount: req.msg.amount,
            user_to_network_tx_id: None,
            network_to_target_tx_id: None,
            vault_to_network_tx_id: None,
            final_solver_id: final_solver_id.clone(),
            error_message: Some(error_msg), // This is the actual chain error!
        }))
    } else {
        // No transaction ID and no error after waiting - still processing or timeout
        Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "timeout".to_string(),
            signer_address: user_registration.ethereum_address.clone(),
            is_registered: true,
            amount: req.msg.amount,
            user_to_network_tx_id: None,
            network_to_target_tx_id: None,
            vault_to_network_tx_id: None,
            final_solver_id,
            error_message: Some(format!(
                "Transaction processing timeout. Intent hash: {}. The transaction may still be processing or may have failed. Please check the status later.",
                intent_hash_hex
            )),
        }))
    }
}

// Helper function to get the actual DKG secret share from shared state
async fn get_actual_dkg_secret_share(
    dkg_storage: std::sync::Arc<DkgStorage>,
) -> Option<k256::Scalar> {
    match dkg_storage.get_final_secret().await {
        Ok(Some(secret)) => Some(secret),
        Ok(None) => {
            warn!("DKG is not completed yet, cannot retrieve secret share");
            None
        }
        Err(e) => {
            warn!("Failed to retrieve DKG secret share: {}", e);
            None
        }
    }
}

pub fn normalize_eth_signature(sig_hex: &str) -> anyhow::Result<([u8; 64], u8)> {
    let s = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("hex decode signature: {}", e))?;
    if bytes.len() != 65 {
        return Err(anyhow::anyhow!(
            "signature must be 65 bytes r||s||v, got {}",
            bytes.len()
        ));
    }

    let mut compact = [0u8; 64];
    compact.copy_from_slice(&bytes[0..64]);

    let mut v = bytes[64];
    // Normalize v to {0,1}
    v = if v >= 35 {
        (v - 35) % 2 // EIP-155 parity
    } else if v >= 27 {
        v - 27 // 27/28 -> 0/1
    } else {
        v // already 0/1?
    };
    if v > 1 {
        return Err(anyhow::anyhow!("invalid recovery id v={}", v));
    }
    Ok((compact, v))
}

pub fn recover_eth_address_secp(
    msg: &[u8],
    compact: &[u8; 64],
    v: u8,
    use_personal_prefix: bool,
) -> anyhow::Result<String> {
    let rid = RecoveryId::from_i32(v as i32).map_err(|e| anyhow::anyhow!("recovery id: {}", e))?;
    let rsig = RecoverableSignature::from_compact(compact, rid)
        .map_err(|e| anyhow::anyhow!("recoverable sig: {}", e))?;

    // Hash message
    let hash = if use_personal_prefix {
        // EIP-191 "\x19Ethereum Signed Message:\n{len}{msg}"
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(msg);
        h.finalize()
    } else {
        Keccak256::digest(msg)
    };

    let secp = Secp256k1::new();
    let m = Message::from_digest_slice(&hash).map_err(|e| anyhow::anyhow!("message: {}", e))?;
    let pk: PublicKey = secp
        .recover_ecdsa(&m, &rsig)
        .map_err(|e| anyhow::anyhow!("recover pk: {}", e))?;

    // ETH address = keccak(uncompressed_pubkey[1..])[12..]
    let uncompressed = pk.serialize_uncompressed(); // 65 bytes: 0x04 || X || Y
    let keccak = Keccak256::digest(&uncompressed[1..]);
    let mut addr20 = [0u8; 20];
    addr20.copy_from_slice(&keccak[12..]); // last 20 bytes
    Ok(to_checksum_address(&addr20))
}

async fn handle_get_user_info(
    ethereum_address: String,
    user_registry: std::sync::Arc<DatabaseUserRegistry>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🔍 HTTP: Received user info request for address: {}",
        ethereum_address
    );

    // Input validation
    let addr_cs = match validate_ethereum_address(&ethereum_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!(
                "❌ HTTP: Address validation failed for '{}': {:?}",
                ethereum_address, e
            );
            let error_response = UserInfoResponse {
                status: "error".to_string(),
                user_id: None,
                ethereum_address: None,
                hmac_constant: None,
                has_tweaked_share: None,
                has_user_group_key: None,
                derived_eth_address: None,
                derived_btc_address: None,
                created_at: None,
                error: Some(e.to_error_response()),
            };
            return Ok(warp::reply::json(&error_response));
        }
    };

    info!(
        "🔍 HTTP: Looking up user info for (normalized): {}",
        addr_cs
    );

    // Database operation with error handling
    match user_registry.get_user_by_address(&addr_cs).await {
        Some(registration) => {
            info!("✅ HTTP: Found user info for {}", addr_cs);

            // Successful response
            let response = UserInfoResponse {
                status: "success".to_string(),
                user_id: Some(registration.user_id),
                ethereum_address: Some(registration.ethereum_address),
                hmac_constant: Some(hex::encode(registration.hmac_constant)),
                has_tweaked_share: Some(registration.tweaked_secret_share.is_some()),
                has_user_group_key: Some(registration.user_group_key.is_some()),
                derived_eth_address: registration.derived_eth_address,
                derived_btc_address: registration.derived_btc_address,
                created_at: Some(registration.created_at.to_rfc3339()),
                error: None,
            };

            Ok(warp::reply::json(&response))
        }
        None => {
            info!("❌ HTTP: User not found for {}", addr_cs);

            // User not found response
            let error_response = UserInfoResponse {
                status: "error".to_string(),
                user_id: None,
                ethereum_address: None,
                hmac_constant: None,
                has_tweaked_share: None,
                has_user_group_key: None,
                derived_eth_address: None,
                derived_btc_address: None,
                created_at: None,
                error: Some(
                    RpcError::UserNotFound(format!("User with address {} not found", addr_cs))
                        .to_error_response(),
                ),
            };

            Ok(warp::reply::json(&error_response))
        }
    }
}

async fn handle_get_node_id(node_id: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&NodeIdResponse { node_id }))
}

async fn handle_get_status(
    _message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("here at handle status!! ");
    Ok(warp::reply::json(&NodeStatus {
        peer_id: "dummy-peer-id".to_string(),
        connected_peers: 0,
        dkg_status: "unknown".to_string(),
        is_ready: true,
    }))
}

async fn handle_heartbeat() -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&HeartbeatResponse {
        status: "alive".to_string(),
    }))
}

async fn handle_get_uptime(
    start_time: std::sync::Arc<std::time::Instant>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let uptime = start_time.elapsed().as_secs();
    Ok(warp::reply::json(&UptimeResponse {
        uptime_seconds: uptime,
    }))
}

async fn handle_solver_reward(
    req: SolverRewardRequest,
    user_registry: std::sync::Arc<DatabaseUserRegistry>,
    dkg_storage: std::sync::Arc<DkgStorage>,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🔍 HTTP: solver_reward request");

    let (compact, v) = match normalize_eth_signature(&req.signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ Invalid signature: {}", e);
            return Ok(warp::reply::json(&SolverRewardResponse {
                status: "error".to_string(),
                solver_address: "".to_string(),
                reward: None,
                error_message: Some(format!("Invalid signature: {}", e)),
            }));
        }
    };

    let msg_bytes = req.msg.as_bytes();
    let signer = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
        Ok(addr) => addr,
        Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
            Ok(addr) => addr,
            Err(e2) => {
                error!(
                    "❌ Failed to recover address: personal_sign={}, raw={}",
                    e1, e2
                );
                return Ok(warp::reply::json(&SolverRewardResponse {
                    status: "error".to_string(),
                    solver_address: "".to_string(),
                    reward: None,
                    error_message: Some(format!(
                        "Failed to recover signature: personal_sign={}, raw={}",
                        e1, e2
                    )),
                }));
            }
        },
    };

    let provided = match checksum_from_any(&req.address) {
        Ok(a) => a,
        Err(e) => {
            return Ok(warp::reply::json(&SolverRewardResponse {
                status: "error".to_string(),
                solver_address: signer,
                reward: None,
                error_message: Some(format!("Invalid address: {}", e)),
            }));
        }
    };

    if signer != provided {
        return Ok(warp::reply::json(&SolverRewardResponse {
            status: "error".to_string(),
            solver_address: signer,
            reward: None,
            error_message: Some("Recovered address does not match provided address".to_string()),
        }));
    }

    // Use user registry's reward storage instead of direct reward storage
    let reward_opt = user_registry.get_solver_reward_btc(&signer).await;
    let reward_str = reward_opt.as_ref().map(|r| r.to_string());

    if let Some(reward_u256) = reward_opt {
        let reward_u128 = reward_u256.as_u128();

        // Create dummy transaction representing solver reward
        let from_addr = match dkg_storage.get_final_public().await {
            Ok(Some(pk)) => crate::utils::get_eth_address_from_group_key(pk),
            _ => "0x0".to_string(),
        };

        let dummy_tx = DummyTransaction {
            to: signer.clone(),
            value: format!("0x{:x}", reward_u128),
            nonce: 0,
            gas_limit: 21_000,
            gas_price: "0x0".to_string(),
            chain_id: 1,
        };
        info!(
            "🧾 [HTTP] Created solver reward tx from {} to {} amount {}",
            from_addr, signer, reward_u128
        );

        let mut tx_sender = message_tx.lock().await;
        if let Err(e) = tx_sender
            .send(ChannelMessage::SolverReward {
                solver_address: signer.clone(),
                reward: reward_u128,
            })
            .await
        {
            warn!("Failed to send solver reward message: {}", e);
        }
    }
    Ok(warp::reply::json(&SolverRewardResponse {
        status: "success".to_string(),
        solver_address: signer,
        reward: reward_str,
        error_message: None,
    }))
}

async fn handle_get_dkg_status(
    dkg_storage: std::sync::Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🔍 HTTP: Checking DKG status");

    let secret_share_available = match dkg_storage.get_final_secret().await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            warn!("Failed to read DKG secret share: {}", e);
            false
        }
    };
    let is_completed = secret_share_available;

    info!(
        "✅ HTTP: DKG status retrieved - completed: {}, secret_share_available: {}",
        is_completed, secret_share_available
    );

    Ok(warp::reply::json(&DKGStatusResponse {
        status: "success".to_string(),
        dkg_status: Some(if is_completed {
            "Completed".to_string()
        } else {
            "NotStarted".to_string()
        }),
        secret_share_available,
        message: if is_completed {
            "DKG completed successfully".to_string()
        } else {
            "DKG not completed yet".to_string()
        },
    }))
}

async fn handle_start_dkg(
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🚀 HTTP: RPC request to start DKG");

    // Wrap the DKG request in a GossipsubMessage
    let dkg_request = RPCRequest::StartADKG;
    let gossipsub_msg = crate::types::GossipsubMessage::DKGCommand(dkg_request);
    let dkg_data = serde_json::to_vec(&gossipsub_msg).map_err(|e| {
        warn!("Failed to serialize DKG request: {}", e);
        warp::reject::custom(TransactionError::SerializationError)
    })?;

    let tx_sender = message_tx.lock().await;
    if let Err(e) = tx_sender
        .send(ChannelMessage::Broadcast {
            topic: "dkg-commands".to_string(),
            data: dkg_data,
        })
        .await
    {
        warn!("Failed to send DKG request to network: {:?}", e);
        return Err(warp::reject::custom(TransactionError::NetworkError));
    }

    info!("✅ HTTP: DKG start request sent to network");
    Ok(warp::reply::json(&TransactionResponse {
        tx_hash: "dkg-start-request".to_string(),
        status: "initiated".to_string(),
        message: "DKG start request sent to P2P network".to_string(),
    }))
}

async fn handle_get_reward_solver(
    req: GetRewardSolverRequest,
    user_registry: std::sync::Arc<DatabaseUserRegistry>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🔍 HTTP: get_reward_solver request for solver: {}", req.solver_address);

    // Validate solver_address
    if req.solver_address.trim().is_empty() {
        return Ok(warp::reply::json(&GetRewardSolverResponse {
            status: "error".to_string(),
            solver_address: req.solver_address,
            reward_btc: None,
            reward_tics: None,
            message: "Solver address cannot be empty".to_string(),
            error_message: Some("Solver address is required".to_string()),
        }));
    }

    // Validate Ethereum address format
    let normalized_address = match checksum_from_any(&req.solver_address) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("❌ Invalid solver address format: {}", e);
            return Ok(warp::reply::json(&GetRewardSolverResponse {
                status: "error".to_string(),
                solver_address: req.solver_address,
                reward_btc: None,
                reward_tics: None,
                message: "Invalid solver address format".to_string(),
                error_message: Some(format!("Invalid address format: {}", e)),
            }));
        }
    };

    // Get solver rewards using user registry (both BTC and TICS)
    let reward_btc = user_registry.get_solver_reward_btc(&normalized_address).await;
    let reward_tics = user_registry.get_solver_reward_tics(&normalized_address).await;

    let reward_btc_str = reward_btc.as_ref().map(|v| v.to_string());
    let reward_tics_str = reward_tics.as_ref().map(|v| v.to_string());

    // For backward compatibility, keep `reward` as the sum if both exist, else whichever exists, else 0
    let legacy_reward = match (reward_btc, reward_tics) {
        (Some(btc), Some(tics)) => (btc + tics).to_string(),
        (Some(btc), None) => btc.to_string(),
        (None, Some(tics)) => tics.to_string(),
        (None, None) => "0".to_string(),
    };

    info!(
        "✅ Rewards for solver {} -> btc: {:?}, tics: {:?}",
        normalized_address, reward_btc_str, reward_tics_str
    );

    Ok(warp::reply::json(&GetRewardSolverResponse {
        status: "success".to_string(),
        solver_address: normalized_address,
        reward_btc: reward_btc_str,
        reward_tics: reward_tics_str,
        message: "Solver rewards retrieved successfully".to_string(),
        error_message: None,
    }))
}

#[derive(Debug)]
pub enum TransactionError {
    SerializationError,
    NetworkError,
    InvalidRequest,
    PricingUnavailable,
    Overflow,
}

impl warp::reject::Reject for TransactionError {}
