use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;
use warp::Filter;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::types::{rpc::RPCRequest, ChannelMessage};
use crate::user_registry::UserRegistry;

// Shared state for DKG secret share
#[derive(Debug, Clone)]
pub struct DKGSharedState {
    pub secret_share: Option<k256::Scalar>,
    pub is_completed: bool,
}

impl DKGSharedState {
    pub fn new() -> Self {
        Self {
            secret_share: None,
            is_completed: false,
        }
    }
    
    pub fn set_secret_share(&mut self, secret_share: k256::Scalar) {
        self.secret_share = Some(secret_share);
        self.is_completed = true;
    }
    
    pub fn get_secret_share(&self) -> Option<k256::Scalar> {
        self.secret_share
    }
    
    pub fn is_completed(&self) -> bool {
        self.is_completed
    }
}

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
    pub path: Vec<u8>,
    pub transaction_hash: String,
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
pub struct UserRegistrationRequest {
    pub ethereum_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistrationResponse {
    pub status: String,
    pub message: String,
    pub address_1: String,
    pub address_2: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGStatusResponse {
    pub status: String,
    pub dkg_status: Option<String>,
    pub secret_share_available: bool,
    pub message: String,
}

// gRPC service definition
#[derive(Default)]
pub struct MpcRpcService {
    message_tx: Option<mpsc::Sender<ChannelMessage>>,
    user_registry: Option<UserRegistry>,
}

impl MpcRpcService {
    pub fn new(message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            message_tx: Some(message_tx),
            user_registry: None,
        }
    }

    pub fn with_user_registry(mut self, user_registry: UserRegistry) -> Self {
        self.user_registry = Some(user_registry);
        self
    }

    pub fn get_message_tx(&self) -> Option<mpsc::Sender<ChannelMessage>> {
        self.message_tx.clone()
    }

    pub fn get_user_registry(&self) -> Option<&UserRegistry> {
        self.user_registry.as_ref()
    }
}

// Note: gRPC service implementation removed for now
// Focus on HTTP server implementation

// HTTP server implementation using warp
pub async fn start_http_server(
    message_tx: mpsc::Sender<ChannelMessage>, 
    port: u16,
    user_registry: UserRegistry,
    dkg_state: Arc<RwLock<DKGSharedState>>,
) -> Result<()> {
    let message_tx = std::sync::Arc::new(tokio::sync::Mutex::new(message_tx));
    let user_registry = std::sync::Arc::new(user_registry);
    let dkg_state = std::sync::Arc::new(dkg_state);

    // POST /submit_transaction
    let submit_tx = warp::path("submit_transaction")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_submit_transaction);

    // POST /deposit_intent
    let deposit_intent = warp::path("deposit_intent")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_deposit_intent);

    // POST /register_user
    let register_user = warp::path("register_user")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_user_registry(user_registry.clone()))
        .and(with_dkg_state(dkg_state.clone()))
        .and_then(handle_register_user);

    // GET /user_info/{ethereum_address}
    let get_user_info = warp::path("user_info")
        .and(warp::path::param())
        .and(warp::get())
        .and(with_user_registry(user_registry.clone()))
        .and_then(handle_get_user_info);

    // GET /status
    let get_status = warp::path("status")
        .and(warp::get())
        .and(with_message_tx(message_tx.clone()))
        .and_then(|message_tx| handle_get_status(message_tx));

    // GET /dkg_status
    let get_dkg_status = warp::path("dkg_status")
        .and(warp::get())
        .and(with_dkg_state(dkg_state.clone()))
        .and_then(handle_get_dkg_status);

    // POST /start_dkg
    let start_dkg = warp::path("start_dkg")
        .and(warp::post())
        .and(with_message_tx(message_tx))
        .and_then(|message_tx| handle_start_dkg(message_tx));

    let routes = submit_tx.or(deposit_intent).or(register_user).or(get_user_info).or(get_status).or(get_dkg_status).or(start_dkg);

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
    user_registry: std::sync::Arc<UserRegistry>,
) -> impl Filter<
    Extract = (std::sync::Arc<UserRegistry>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || user_registry.clone())
}

fn with_dkg_state(
    dkg_state: std::sync::Arc<Arc<RwLock<DKGSharedState>>>,
) -> impl Filter<
    Extract = (std::sync::Arc<Arc<RwLock<DKGSharedState>>>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || dkg_state.clone())
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

async fn handle_deposit_intent(
    intent: DepositIntent,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📝 HTTP: Received deposit intent: {:?}", intent);

    let intent_id = format!("intent-{}", Uuid::new_v4());
    let deposit_intent_msg = ChannelMessage::DepositIntent {
        intent: intent.clone(),
        intent_id: intent_id.clone(),
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
    user_registry: std::sync::Arc<UserRegistry>,
    dkg_state: std::sync::Arc<Arc<RwLock<DKGSharedState>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("👤 HTTP: Received user registration request for address: {}", request.ethereum_address);

    // Register the user in the global registry
    match user_registry.register_user(&request.ethereum_address).await {
        Ok(registration) => {
            info!("✅ HTTP: User registration successful for address: {}", request.ethereum_address);
            
            // Get the actual original secret share from DKG shared state
            if let Some(original_secret_share) = get_actual_dkg_secret_share(dkg_state).await {
                // Compute the tweaked secret share using the actual DKG secret share
                // but don't return it in the response - keep it private
                match user_registry.compute_tweaked_secret_share(&request.ethereum_address, &original_secret_share).await {
                    Ok(_tweaked_share) => {
                        info!("🔐 HTTP: Tweaked secret share computed and stored privately for address: {}", request.ethereum_address);
                    }
                    Err(e) => {
                        warn!("⚠️ HTTP: Failed to compute tweaked secret share for address {}: {}", request.ethereum_address, e);
                        // Continue with registration even if tweaked share computation fails
                    }
                }
            } else {
                warn!("⚠️ HTTP: Could not retrieve DKG secret share for tweaked share computation");
                // Continue with registration even if DKG secret share is not available
            }
            
            // Return the HMAC constant as hex strings for the two addresses
            let hmac_hex = hex::encode(registration.hmac_constant);
            
            Ok(warp::reply::json(&UserRegistrationResponse {
                status: "success".to_string(),
                message: "User registered successfully".to_string(),
                address_1: hmac_hex.clone(),
                address_2: hmac_hex, // For now, returning the same HMAC constant for both addresses
            }))
        }
        Err(e) => {
            warn!("❌ HTTP: User registration failed for address {}: {}", request.ethereum_address, e);
            
            Err(warp::reject::custom(TransactionError::NetworkError))
        }
    }
}

// Helper function to get the actual DKG secret share from shared state
async fn get_actual_dkg_secret_share(dkg_state: std::sync::Arc<Arc<RwLock<DKGSharedState>>>) -> Option<k256::Scalar> {
    // Access the DKG shared state
    let dkg_state_guard = dkg_state.read().await;
    
    // Check if DKG is completed and get the secret share
    if dkg_state_guard.is_completed() {
        dkg_state_guard.get_secret_share()
    } else {
        warn!("DKG is not completed yet, cannot retrieve secret share");
        None
    }
}

async fn handle_get_user_info(
    ethereum_address: String,
    user_registry: std::sync::Arc<UserRegistry>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🔍 HTTP: Looking up user info for address: {}", ethereum_address);

    match user_registry.get_user_by_address(&ethereum_address).await {
        Some(registration) => {
            info!("✅ HTTP: Found user info for address: {}", ethereum_address);
            
            // Create a response that includes the tweaked secret share status but not the actual value
            let response = serde_json::json!({
                "user_id": registration.user_id,
                "ethereum_address": registration.ethereum_address,
                "hmac_constant": hex::encode(registration.hmac_constant),
                "has_tweaked_share": registration.tweaked_secret_share.is_some(),
                "created_at": registration.created_at
            });
            
            Ok(warp::reply::json(&response))
        }
        None => {
            info!("❌ HTTP: User not found for address: {}", ethereum_address);
            Err(warp::reject::not_found())
        }
    }
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

async fn handle_get_dkg_status(
    dkg_state: std::sync::Arc<Arc<RwLock<DKGSharedState>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🔍 HTTP: Checking DKG status");

    let dkg_state_guard = dkg_state.read().await;
    
    let is_completed = dkg_state_guard.is_completed();
    let secret_share_available = dkg_state_guard.get_secret_share().is_some();
    
    info!("✅ HTTP: DKG status retrieved - completed: {}, secret_share_available: {}", is_completed, secret_share_available);
    
    Ok(warp::reply::json(&DKGStatusResponse {
        status: "success".to_string(),
        dkg_status: Some(if is_completed { "Completed".to_string() } else { "NotStarted".to_string() }),
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
}

impl warp::reject::Reject for TransactionError {}
