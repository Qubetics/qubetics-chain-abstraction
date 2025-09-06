use crate::database::DkgStorage;
use crate::types::{rpc::RPCRequest, ChannelMessage};
use crate::user_registry::{
    checksum_from_any, to_checksum_address, DatabaseUserRegistry, TransactionStatus,
};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha3::Keccak256;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;
use warp::Filter;

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
    pub timestamp: u64, // Unix timestamp in seconds
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
    pub signature: String,
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
    pub used_personal_sign_prefix: bool,
    pub tx_id: Option<String>,
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
        return Err(RpcError::InvalidAddress("Address cannot be empty".to_string()));
    }
    
    if !address.starts_with("0x") && address.len() != 42 {
        return Err(RpcError::InvalidAddress("Address must be 42 characters and start with 0x".to_string()));
    }
    
    match checksum_from_any(address) {
        Ok(normalized) => Ok(normalized),
        Err(e) => Err(RpcError::InvalidAddress(format!("Invalid address format: {}", e))),
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
        .and_then(handle_user_mpc_deposit);

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
        .or(heartbeat)
        .or(uptime);

    info!("🌐 Starting HTTP RPC server on port {}", port);
    warp::serve(routes).run(([127, 0, 0, 1], port)).await;
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
    info!("📝 HTTP: Received transaction: {:?}", tx);

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

    info!("✅ HTTP: Transaction submitted to network: {}", tx_hash);

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

pub async fn handle_deposit_intent(
    intent: DepositIntent,
    user_eth_address: Option<String>,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📝 HTTP: Received deposit intent request: {:?}", intent);
    info!(
        "📝 HTTP: User eth address for signing: {:?}",
        user_eth_address
    );

    let intent_id = format!("intent-{}", Uuid::new_v4());
    let deposit_intent_msg = ChannelMessage::DepositIntent {
        intent: intent.clone(),
        intent_id: intent_id.clone(),
        user_eth_address: user_eth_address.clone(),
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
    info!("👤 HTTP: Received user registration request for address: {}", request.ethereum_address);

    // Input validation
    let addr_cs = match validate_ethereum_address(&request.ethereum_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!("❌ HTTP: Address validation failed for '{}': {:?}", request.ethereum_address, e);
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
            error: Some(RpcError::InvalidRequest("User is already registered".to_string()).to_error_response()),
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
            error: Some(RpcError::DkgNotReady("DKG secret share not available".to_string()).to_error_response()),
        };
        return Ok(warp::reply::json(&error_response));
    }

    // Attempt user registration
    match user_registry
        .register_user(&addr_cs, dkg_secret_share.as_ref(), &node_id)
        .await
    {
        Ok(registration) => {
            info!("✅ HTTP: User registration successful for address: {}", addr_cs);

            // Log tweaked secret share status
            if registration.tweaked_secret_share.is_some() {
                info!("🔑 HTTP: Computed and stored tweaked secret share for user: {}", addr_cs);
            } else {
                warn!("⚠️ HTTP: No tweaked secret share computed for user: {}", addr_cs);
            }

            // Broadcast to other nodes via P2P network
            let user_reg_msg = ChannelMessage::UserRegistration {
                ethereum_address: addr_cs.clone(),
                node_id: node_id.to_string(),
            };

            // Send via message channel to be picked up by network layer
            if let Ok(tx) = message_tx.try_lock() {
                if let Err(e) = tx.send(user_reg_msg).await {
                    error!("❌ Failed to send user registration message to network: {}", e);
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
                        if updated_user.derived_eth_address.is_some() && updated_user.derived_btc_address.is_some() {
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
                    info!("⏳ Attempt {}/{}: Derived addresses not ready yet, waiting 1 second...", attempts, MAX_ATTEMPTS);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }

            if attempts >= MAX_ATTEMPTS {
                warn!("⚠️ Derived addresses not available after {} attempts", MAX_ATTEMPTS);
            }

            // Log derived addresses if available
            if let Some(eth_addr) = &final_registration.derived_eth_address {
                info!("📬 HTTP: Derived ETH address for {}: {}", addr_cs, eth_addr);
            }
            if let Some(btc_addr) = &final_registration.derived_btc_address {
                info!("📬 HTTP: Derived BTC address for {}: {}", addr_cs, btc_addr);
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
            error!("❌ HTTP: User registration failed for address {}: {}", addr_cs, e);

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
) -> Option<String> {
    let intent_hash_hex = hex::encode(intent_hash);

    // Fetch any recorded transaction IDs for this intent hash
    if let Some(tx_ids) = user_registry
        .get_intent_transaction_ids(&intent_hash_hex)
        .await
    {
        // Candidate transaction IDs associated with this intent
        let candidates = [
            tx_ids.user_to_network_tx_id.clone(),
            tx_ids.network_to_target_tx_id.clone(),
        ];

        // Return the first transaction ID that has an entry in the
        // txid -> status mapping
        for tx_id in candidates.iter().flatten() {
            if user_registry.get_transaction_status(tx_id).await.is_some() {
                return Some(tx_id.clone());
            }
        }
    }

    None
}

/// Wait for a transaction ID or chain error associated with the given intent hash.
/// Polls the database frequently to return as soon as possible and times out
/// after the provided number of seconds.
async fn wait_for_transaction_result(
    user_registry: &DatabaseUserRegistry,
    intent_hash: &[u8],
    timeout_secs: u64,
) -> (Option<String>, Option<String>) {
    let start = std::time::Instant::now();
    let intent_hash_hex = hex::encode(intent_hash);
    let poll_interval = tokio::time::Duration::from_millis(250);
    let timeout = tokio::time::Duration::from_secs(timeout_secs);

    loop {
        // Check for transaction id
        if let Some(tx_id) = get_transaction_id_for_intent(user_registry, intent_hash).await {
            return (Some(tx_id), None);
        }

        // Check for any recorded chain error
        if let Some(tx_ids) = user_registry
            .get_intent_transaction_ids(&intent_hash_hex)
            .await
        {
            if let Some(error_msg) = tx_ids.error_message {
                return (None, Some(error_msg));
            }
        }

        if start.elapsed() >= timeout {
            break;
        }

        tokio::time::sleep(poll_interval).await;
    }

    (None, None)
}

async fn handle_user_mpc_deposit(
    req: UserMpcDepositRequest,
    user_registry: std::sync::Arc<DatabaseUserRegistry>,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🧾 HTTP: user_mpc_deposit: amount={}, sig_len={}",
        req.msg.amount,
        req.signature.len()
    );

    // If transaction ID and status are provided, update the database accordingly
    if let (Some(ref tx_id), Some(ref status_str)) = (&req.tx_id, &req.status) {
        info!(
            "🔄 HTTP: updating tx status for tx_id={} to {}",
            tx_id, status_str
        );

        let status_enum = match status_str.to_lowercase().as_str() {
            "pending" => Some(TransactionStatus::Pending),
            "rejected" => Some(TransactionStatus::Rejected),
            "confirmed" => Some(TransactionStatus::Confirmed),
            other => {
                warn!("❌ Invalid transaction status received: {}", other);
                None
            }
        };

        if let Some(status_enum) = status_enum {
            if let Err(e) = user_registry
                .update_transaction_status(tx_id, status_enum.clone())
                .await
            {
                error!("Failed to update transaction status: {}", e);
            } else {
                info!("✅ Updated transaction status for {}: {:?}", tx_id, status_enum);
            }
        }
    }

    // Serialize the DepositIntent to match the client's JSON.stringify() format
    // Use compact JSON serialization (no spaces) to match JavaScript's JSON.stringify()
    let intent_json = serde_json::to_string(&req.msg).unwrap();
    let intent_bytes = intent_json.as_bytes();
    let intent_hash = Keccak256::digest(intent_bytes);

    info!(
        "🔐 Processing MPC deposit - Intent hash: {:?}, Amount: {}",
        intent_hash, req.msg.amount
    );
    info!("📝 Server JSON serialization: {}", intent_json);
    info!(
        "📏 JSON length: {}, First 100 chars: {}",
        intent_json.len(),
        if intent_json.len() > 100 {
            &intent_json[0..100]
        } else {
            &intent_json
        }
    );

    // Normalize signature (expects r||s||v 65 bytes in hex)
    let (compact, v) = match normalize_eth_signature(&req.signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ Failed to normalize signature: {}", e);
            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                status: "error".to_string(),
                signer_address: "".to_string(),
                is_registered: false,
                amount: 0,
                used_personal_sign_prefix: false,
                tx_id: None,
                error_message: Some(format!("Invalid signature format: {}", e)),
            }));
        }
    };

    // Try personal_sign first, then raw keccak(msg)
    let (signer, used_personal) = match recover_eth_address_secp(intent_bytes, &compact, v, true) {
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
                        used_personal_sign_prefix: false,
                        tx_id: None,
                        error_message: Some(format!(
                            "Failed to recover signature: personal_sign={}, raw={}",
                            e1, e2
                        )),
                    }));
                }
            }
        }
    };

    info!("✅ Recovered signer address: {}", signer);

    // Check if user is registered
    let is_registered = user_registry.get_user_by_address(&signer).await.is_some();

    if !is_registered {
        warn!("⚠️ Unregistered user attempting MPC deposit: {}", signer);
        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            signer_address: signer,
            is_registered: false,
            amount: 0,
            used_personal_sign_prefix: used_personal,
            tx_id: None,
            error_message: Some(
                "User is not registered. Please register first before making deposits.".to_string(),
            ),
        }));
    }

    // Store intent hash in user registry
    if let Err(e) = user_registry
        .store_intent_hash(intent_hash.to_vec(), &signer, &req.msg)
        .await
    {
        error!("❌ Failed to store intent hash: {}", e);
        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            signer_address: signer.clone(),
            is_registered: true,
            amount: 0,
            used_personal_sign_prefix: used_personal,
            tx_id: None,
            error_message: Some(format!("Failed to process deposit intent: {}", e)),
        }));
    }

    info!("✅ Intent hash stored successfully for user: {}", signer);

    // Broadcast intent to other nodes
    let intent_hash_hex = hex::encode(&intent_hash);
    let broadcast_message = ChannelMessage::Broadcast {
        topic: "intent-broadcast".to_string(),
        data: serde_json::to_vec(&crate::types::GossipsubMessage::IntentBroadcast {
            intent: req.msg.clone(),
            signature: req.signature.clone(),
            intent_hash: intent_hash_hex.clone(),
        })
        .unwrap_or_default(),
    };

    // Send broadcast message
    let tx = message_tx.lock().await;
    if let Err(e) = tx.send(broadcast_message).await {
        warn!("❌ Failed to broadcast intent to other nodes: {}", e);
        // Don't fail the request if broadcasting fails
    } else {
        info!(
            "📡 Successfully broadcasted intent {} to other nodes",
            intent_hash_hex
        );
    }
    drop(tx);

    // Process the deposit intent
    let user_eth_address = if req.tx_id.is_some() {
        None
    } else {
        Some(signer.clone())
    };
    
    // Process the deposit intent
    match handle_deposit_intent(req.msg.clone(), user_eth_address, message_tx).await {
        Ok(_) => {
            info!(
                "✅ Deposit intent processed successfully for user: {}",
                signer
            );
        }
        Err(e) => {
            error!("❌ Failed to process deposit intent: {:?}", e);

            // Just return the raw error message as it is
            let error_message = format!("{:?}", e);

            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                status: "error".to_string(),
                signer_address: signer.clone(),
                is_registered: true,
                amount: req.msg.amount,
                used_personal_sign_prefix: used_personal,
                tx_id: None,
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
    let (tx_id, chain_error) = wait_for_transaction_result(&user_registry, &intent_hash, 10).await;

    // Log the transaction ID if one was recorded
    if let Some(ref tx_id_str) = tx_id {
        info!("✅ Transaction completed successfully with ID: {:?}", tx_id_str);
    }

    if let Some(tx_id) = tx_id {
        // Success - got transaction ID
        Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "success".to_string(),
            signer_address: signer,
            is_registered: true,
            amount: req.msg.amount,
            used_personal_sign_prefix: used_personal,
            tx_id: Some(tx_id),
            error_message: None,
        }))
    } else if let Some(error_msg) = chain_error {
        // Chain error occurred - return the actual error from blockchain
        Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            signer_address: signer,
            is_registered: true,
            amount: req.msg.amount,
            used_personal_sign_prefix: used_personal,
            tx_id: None,
            error_message: Some(error_msg), // This is the actual chain error!
        }))
    } else {
        // No transaction ID and no error after waiting - still processing or timeout
        Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "timeout".to_string(),
            signer_address: signer,
            is_registered: true,
            amount: req.msg.amount,
            used_personal_sign_prefix: used_personal,
            tx_id: None,
            error_message: Some(format!("Transaction processing timeout. Intent hash: {}. The transaction may still be processing or may have failed. Please check the status later.", intent_hash_hex)),
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
    info!("🔍 HTTP: Received user info request for address: {}", ethereum_address);

    // Input validation
    let addr_cs = match validate_ethereum_address(&ethereum_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!("❌ HTTP: Address validation failed for '{}': {:?}", ethereum_address, e);
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

    info!("🔍 HTTP: Looking up user info for (normalized): {}", addr_cs);

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
                error: Some(RpcError::UserNotFound(format!("User with address {} not found", addr_cs)).to_error_response()),
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

#[derive(Debug)]
pub enum TransactionError {
    SerializationError,
    NetworkError,
    InvalidRequest,
}

impl warp::reject::Reject for TransactionError {}
