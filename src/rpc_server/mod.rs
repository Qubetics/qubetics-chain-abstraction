use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};
use warp::Filter;

use crate::database::DatabaseManager;
use crate::types::{rpc::RPCRequest, ChannelMessage, DepositIntent};

/// Validate an intent before processing
fn validate_intent(intent: &DepositIntent) -> Result<(), (String, String)> {
    // Validate amount
    if intent.amount == 0 {
        return Err(("INVALID_AMOUNT".to_string(), "Amount must be greater than 0".to_string()));
    }

    // Validate addresses (basic format check)
    if intent.source_address.trim().is_empty() {
        return Err(("INVALID_SOURCE_ADDRESS".to_string(), "Source address cannot be empty".to_string()));
    }

    if intent.target_address.trim().is_empty() {
        return Err(("INVALID_TARGET_ADDRESS".to_string(), "Target address cannot be empty".to_string()));
    }

    // Validate chain names
    let supported_chains = ["tics", "qubetics", "bitcoin", "btc", "sepolia"];
    if !supported_chains.contains(&intent.source_chain.to_lowercase().as_str()) {
        return Err(("UNSUPPORTED_SOURCE_CHAIN".to_string(), 
                   format!("Source chain '{}' is not supported. Supported chains: {}", 
                          intent.source_chain, supported_chains.join(", "))));
    }

    if !supported_chains.contains(&intent.target_chain.to_lowercase().as_str()) {
        return Err(("UNSUPPORTED_TARGET_CHAIN".to_string(), 
                   format!("Target chain '{}' is not supported. Supported chains: {}", 
                          intent.target_chain, supported_chains.join(", "))));
    }

    // Basic qubetics address validation (if target is qubetics)
    if matches!(intent.target_chain.to_lowercase().as_str(), "tics" | "qubetics") {
        if !intent.target_address.starts_with("0x") || intent.target_address.len() != 42 {
            return Err(("INVALID_tics_ADDRESS".to_string(), 
                       "qubetics address must start with '0x' and be 42 characters long".to_string()));
        }
    }

    // Basic Bitcoin address validation (if target is Bitcoin)
    if matches!(intent.target_chain.to_lowercase().as_str(), "bitcoin" | "btc") {
        // Bitcoin addresses typically start with 1, 3, or bc1 for mainnet, or tb1/2/m/n for testnet
        let first_char = intent.target_address.chars().nth(0).unwrap_or(' ');
        let is_valid_btc = intent.target_address.starts_with("bc1") || 
                          intent.target_address.starts_with("tb1") ||
                          first_char == '1' || first_char == '3' || 
                          first_char == '2' || first_char == 'm' || first_char == 'n';
        
        if !is_valid_btc {
            return Err(("INVALID_BTC_ADDRESS".to_string(), 
                       "Invalid Bitcoin address format".to_string()));
        }
    }

    Ok(())
}

/// Query transaction hash from signing node via message channel
async fn query_transaction_hash_from_signing_node(
    intent_hash: &str,
    message_tx: &tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>,
) -> Option<String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    
    let query_msg = ChannelMessage::QueryTransactionHash {
        intent_hash: intent_hash.to_string(),
        response_tx,
    };
    
    // Send the query
    if let Ok(tx) = message_tx.try_lock() {
        if let Err(e) = tx.send(query_msg).await {
            warn!("Failed to send transaction hash query: {:?}", e);
            return None;
        }
    } else {
        warn!("Failed to acquire message channel lock for transaction hash query");
        return None;
    }
    
    // Wait for response with timeout
    match tokio::time::timeout(std::time::Duration::from_millis(100), response_rx).await {
        Ok(Ok(tx_hash)) => tx_hash,
        Ok(Err(_)) => {
            warn!("Transaction hash query response channel closed");
            None
        }
        Err(_) => {
            warn!("Transaction hash query timed out");
            None
        }
    }
}

/// Query final node ID from signing node via message channel
async fn query_final_node_from_signing_node(
    intent_hash: &str,
    message_tx: &tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>,
) -> Option<String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    
    let query_msg = ChannelMessage::QueryFinalNode {
        intent_hash: intent_hash.to_string(),
        response_tx,
    };
    
    // Send the query
    if let Ok(tx) = message_tx.try_lock() {
        if let Err(e) = tx.send(query_msg).await {
            warn!("Failed to send final node query: {:?}", e);
            return None;
        }
    } else {
        warn!("Failed to acquire message channel lock for final node query");
        return None;
    }
    
    // Wait for response with timeout
    match tokio::time::timeout(std::time::Duration::from_millis(100), response_rx).await {
        Ok(Ok(final_node)) => final_node,
        Ok(Err(_)) => {
            warn!("Final node query response channel closed");
            None
        }
        Err(_) => {
            warn!("Final node query timed out");
            None
        }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub tx_hash: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub peer_id: String,
    pub connected_peers: usize,
    pub dkg_status: String,
    pub is_ready: bool,
}

// gRPC service definition
#[derive(Default)]
pub struct MpcRpcService {
    message_tx: Option<mpsc::Sender<ChannelMessage>>,
}

impl MpcRpcService {
    pub fn new(message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            message_tx: Some(message_tx),
        }
    }

    pub fn get_message_tx(&self) -> Option<mpsc::Sender<ChannelMessage>> {
        self.message_tx.clone()
    }
}

// Note: gRPC service implementation removed for now
// Focus on HTTP server implementation

// HTTP server implementation using warp
pub async fn start_http_server(
    message_tx: mpsc::Sender<ChannelMessage>, 
    db: DatabaseManager,
    port: u16
) -> Result<()> {
    let message_tx = std::sync::Arc::new(tokio::sync::Mutex::new(message_tx));
    let db = std::sync::Arc::new(db);

    // POST /submit_transaction
    let submit_tx = warp::path("submit_transaction")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_message_tx(message_tx.clone()))
        .and(with_database(db.clone()))
        .and_then(handle_submit_transaction);

    // GET /status
    let get_status = warp::path("status")
        .and(warp::get())
        .and(with_message_tx(message_tx.clone()))
        .and(with_database(db.clone()))
        .and_then(handle_get_status);

    // POST /start_dkg
    let start_dkg = warp::path("start_dkg")
        .and(warp::post())
        .and(with_message_tx(message_tx.clone()))
        .and(with_database(db.clone()))
        .and_then(handle_start_dkg);

    // POST /submit_intent
    let submit_intent = warp::path("submit_intent")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_message_tx(message_tx))
        .and(with_database(db.clone()))
        .and_then(handle_submit_intent);

    // GET /intents (new endpoint to list stored intents)
    let list_intents = warp::path("intents")
        .and(warp::get())
        .and(with_database(db.clone()))
        .and_then(handle_list_intents);

    // GET /intent/{hash} (new endpoint to fetch intent by hash)
    let get_intent = warp::path("intent")
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(with_database(db.clone()))
        .and_then(handle_get_intent);

    // GET /intent/{hash}/transaction_hash (new endpoint to get transaction hash for intent)
    let get_intent_tx_hash = warp::path("intent")
        .and(warp::path::param::<String>())
        .and(warp::path("transaction_hash"))
        .and(warp::get())
        .and(with_database(db))
        .and_then(handle_get_intent_transaction_hash);

    let routes = submit_tx.or(get_status).or(start_dkg).or(submit_intent).or(list_intents).or(get_intent).or(get_intent_tx_hash);

    info!("🌐 Starting HTTP RPC server on port {}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
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

fn with_database(
    db: std::sync::Arc<DatabaseManager>,
) -> impl Filter<
    Extract = (std::sync::Arc<DatabaseManager>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || db.clone())
}

async fn handle_submit_transaction(
    tx: DummyTransaction,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
    _db: std::sync::Arc<DatabaseManager>,
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

async fn handle_get_status(
    _message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
    _db: std::sync::Arc<DatabaseManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("here at handle status!! ");
    Ok(warp::reply::json(&NodeStatus {
        peer_id: "dummy-peer-id".to_string(),
        connected_peers: 0,
        dkg_status: "unknown".to_string(),
        is_ready: true,
    }))
}

async fn handle_start_dkg(
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
    _db: std::sync::Arc<DatabaseManager>,
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

async fn handle_submit_intent(
    intent: DepositIntent,
    message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
    db: std::sync::Arc<DatabaseManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("Intent received: {} -> {} ({})", 
          intent.source_chain, intent.target_chain, intent.amount);

    // Validate intent first
    if let Err((error_code, error_message)) = validate_intent(&intent) {
        warn!("Intent validation failed: {} - {}", error_code, error_message);
        
        let response = serde_json::json!({
            "intent_hash": null,
            "transaction_hash": null,
            "solver_id": null,
            "status": "validation_failed",
            "message": format!("Intent validation failed: {}", error_message),
            "error_code": error_code,
            "error_message": error_message
        });
        
        return Ok(warp::reply::json(&response));
    }

    // Check for duplicate intent before processing
    if let Ok(Some(existing_hash)) = db.check_duplicate_intent(&intent) {
        warn!("Duplicate intent detected: {}", existing_hash);
        
        // Return the existing intent information
        let status = db.get_intent_status(&existing_hash).unwrap_or(Some("unknown".to_string()));
        let tx_hash = db.get_intent_transaction_hash(&existing_hash).unwrap_or(None);
        let solver_id = query_final_node_from_signing_node(&existing_hash, &message_tx).await;
        
        let response = serde_json::json!({
            "intent_hash": existing_hash,
            "transaction_hash": tx_hash,
            "solver_id": solver_id,
            "status": "duplicate",
            "message": "This intent has already been submitted. Use the returned hash to check status.",
            "error_code": "DUPLICATE_INTENT",
            "error_message": "An identical intent with the same parameters already exists."
        });
        
        return Ok(warp::reply::json(&response));
    }

    let intent_hash = format!(
        "0x{:x}",
        sha2::Sha256::digest(format!("{:?}", intent).as_bytes())
    );

    // Store intent in database
    if let Err(e) = db.store_intent(&intent_hash, &intent) {
        warn!("Failed to store intent {}: {}", intent_hash, e);
        return Err(warp::reject::custom(TransactionError::DatabaseError));
    }

    // Set status to received
    if let Err(e) = db.update_intent_status(&intent_hash, "received") {
        warn!("Failed to set status for {}: {}", intent_hash, e);
    }

    // Set initial solver to pending
    if let Err(e) = db.update_intent_solver(&intent_hash, "pending") {
        warn!("Failed to set solver for {}: {}", intent_hash, e);
    }

    // Send to local signing node
    let local_msg = ChannelMessage::LocalIntent {
        intent: intent.clone(),
    };

    // Broadcast to network
    let gossipsub_msg = crate::types::GossipsubMessage::Intent(intent.clone());
    let intent_data = serde_json::to_vec(&gossipsub_msg).map_err(|e| {
        warn!("Failed to serialize intent {}: {}", intent_hash, e);
        warp::reject::custom(TransactionError::SerializationError)
    })?;

    // Send both messages quickly and release the lock
    {
        let tx_sender = message_tx.lock().await;
        
        // Send local processing message
        if let Err(e) = tx_sender.send(local_msg).await {
            warn!("Failed local processing for {}: {:?}", intent_hash, e);
            return Err(warp::reject::custom(TransactionError::NetworkError));
        }

        // Send network broadcast message
        if let Err(e) = tx_sender
            .send(ChannelMessage::Broadcast {
                topic: "intents".to_string(),
                data: intent_data,
            })
            .await
        {
            warn!("Failed network broadcast for {}: {:?}", intent_hash, e);
            return Err(warp::reject::custom(TransactionError::NetworkError));
        }
        
        // Lock is automatically released here
    }

    // Status updates will be handled in backend processing functions

    info!("Intent {} processed successfully", intent_hash);

    // Wait for transaction hash to become available from signing node
    info!("⏳ Waiting for transaction hash to be generated for intent {}", intent_hash);
    
    // Give the backend a moment to start processing and potentially detect early errors
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    
    // Quick error check before starting polling loop
    if let Ok(Some(error_code)) = db.get_intent_error_code(&intent_hash) {
        if let Ok(Some(error_message)) = db.get_intent_error_message(&intent_hash) {
            warn!("❌ [EARLY_CHECK] Error detected immediately for intent {}: {} - {}", intent_hash, error_code, error_message);
            
            let solver_id = query_final_node_from_signing_node(&intent_hash, &message_tx).await;
            let status = db.get_intent_status(&intent_hash).unwrap_or(Some("failed".to_string())).unwrap_or("failed".to_string());
            
            let response = serde_json::json!({
                "intent_hash": intent_hash.clone(),
                "transaction_hash": null,
                "solver_id": solver_id,
                "status": status,
                "message": format!("Intent processing failed: {}", error_message),
                "error_code": error_code,
                "error_message": error_message
            });
            return Ok(warp::reply::json(&response));
        }
    }
    
    let timeout_duration = std::time::Duration::from_secs(15); // 15 seconds timeout (reduced)
    let poll_interval = std::time::Duration::from_millis(200); // Check every 200ms (faster polling)
    let start_time = std::time::Instant::now();

    loop {
        // PRIORITY: Check for errors first before anything else
        info!("🔍 [POLLING] Checking for errors for intent {}", intent_hash);
        
        if let Ok(Some(error_code)) = db.get_intent_error_code(&intent_hash) {
            if let Ok(Some(error_message)) = db.get_intent_error_message(&intent_hash) {
                warn!("❌ [POLLING] Error found for intent {}: {} - {}", intent_hash, error_code, error_message);
                
                let solver_id = query_final_node_from_signing_node(&intent_hash, &message_tx).await;
                let status = db.get_intent_status(&intent_hash).unwrap_or(Some("failed".to_string())).unwrap_or("failed".to_string());
                
                info!("📤 [POLLING] Returning error response immediately for intent {}", intent_hash);
                let response = serde_json::json!({
                    "intent_hash": intent_hash.clone(),
                    "transaction_hash": null,
                    "solver_id": solver_id,
                    "status": status,
                    "message": format!("Intent processing failed: {}", error_message),
                    "error_code": error_code,
                    "error_message": error_message
                });
                return Ok(warp::reply::json(&response));
            }
        } else {
            info!("✅ [POLLING] No error found for intent {}, checking for success", intent_hash);
        }

        // Query transaction hash from signing node using round-based lookup
        if let Some(tx_hash) = query_transaction_hash_from_signing_node(&intent_hash, &message_tx).await {
            info!("🎯 [POLLING] Transaction hash retrieved for intent {}: {}", intent_hash, tx_hash);
            
            // Also query the solver ID (final node ID)
            let solver_id = query_final_node_from_signing_node(&intent_hash, &message_tx).await;
            info!("🏆 [POLLING] Solver ID retrieved for intent {}: {:?}", intent_hash, solver_id);
            
            let response = serde_json::json!({
                "intent_hash": intent_hash.clone(),
                "transaction_hash": tx_hash,
                "solver_id": solver_id,
                "status": "completed",
                "message": "Intent processed and transaction broadcasted successfully"
            });
            return Ok(warp::reply::json(&response));
        } else {
            info!("⏳ [POLLING] No transaction hash yet for intent {}, elapsed: {:?}", intent_hash, start_time.elapsed());
            
            // Hash not yet available, check if we've timed out
            if start_time.elapsed() >= timeout_duration {
                warn!("⏰ Timeout waiting for transaction hash for intent {}", intent_hash);
                
                // Check the current status in database
                let current_status = db.get_intent_status(&intent_hash).unwrap_or(Some("timeout".to_string())).unwrap_or("timeout".to_string());
                let solver_id = query_final_node_from_signing_node(&intent_hash, &message_tx).await;
                
                // If status is failed, there might be an error we missed
                let (message, error_info) = if current_status == "failed" {
                    let error_code = db.get_intent_error_code(&intent_hash).unwrap_or(None);
                    let error_message = db.get_intent_error_message(&intent_hash).unwrap_or(None);
                    
                    if let (Some(code), Some(msg)) = (error_code, error_message) {
                        (format!("Intent processing failed: {}", msg), Some((code, msg)))
                    } else {
                        ("Intent processing failed with unknown error.".to_string(), None)
                    }
                } else {
                    ("Transaction processing timed out. Use the polling endpoint to check status.".to_string(), None)
                };
                
                let mut response = json!({
                    "intent_hash": intent_hash.clone(),
                    "transaction_hash": null,
                    "solver_id": solver_id,
                    "status": if current_status == "failed" { "failed" } else { "timeout" },
                    "message": message,
                    "polling_endpoint": format!("/intent/{}/transaction_hash", intent_hash)
                });

                // Add error information if available
                if let Some((error_code, error_message)) = error_info {
                    response["error_code"] = json!(error_code);
                    response["error_message"] = json!(error_message);
                }
                
                return Ok(warp::reply::json(&response));
            }
            
            // Wait before next poll
            tokio::time::sleep(poll_interval).await;
        }
    }
}

async fn handle_list_intents(
    db: std::sync::Arc<DatabaseManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match db.list_intents() {
        Ok(intents) => {
            let mut intent_responses = Vec::new();
            
            for (hash, intent) in intents {
                let status = db.get_intent_status(&hash).unwrap_or_else(|e| {
                    warn!("Failed to get status for {}: {}", hash, e);
                    Some("unknown".to_string())
                });
                
                let solver = db.get_intent_solver(&hash).unwrap_or_else(|e| {
                    warn!("Failed to get solver for {}: {}", hash, e);
                    Some("unknown".to_string())
                });
                
                let status_str = status.unwrap_or_else(|| "unknown".to_string());
                let solver_str = solver.unwrap_or_else(|| "unknown".to_string());
                
                let response = IntentWithStatus {
                    hash,
                    intent,
                    status: status_str,
                    solver: solver_str,
                    solver_id: None, // TODO: Add solver ID lookup if needed
                };
                intent_responses.push(response);
            }

            let count = intent_responses.len();
            info!("Listed {} intents", count);
            
            Ok(warp::reply::json(&IntentListResponse {
                intents: intent_responses,
                count,
            }))
        }
        Err(e) => {
            warn!("Failed to list intents: {}", e);
            Err(warp::reject::custom(TransactionError::DatabaseError))
        }
    }
}

async fn handle_get_intent(
    intent_hash: String,
    db: std::sync::Arc<DatabaseManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🔍 Fetching intent with hash: {}", intent_hash);
    
    match db.get_intent(&intent_hash) {
        Ok(Some(intent)) => {
            let status = db.get_intent_status(&intent_hash).unwrap_or_else(|e| {
                warn!("Failed to get status for {}: {}", intent_hash, e);
                Some("unknown".to_string())
            });

            let solver = db.get_intent_solver(&intent_hash).unwrap_or_else(|e| {
                warn!("Failed to get solver for {}: {}", intent_hash, e);
                Some("unknown".to_string())
            });
            
            let status_str = status.unwrap_or_else(|| "unknown".to_string());
            let solver_str = solver.unwrap_or_else(|| "unknown".to_string());
            
            let response = IntentWithStatus {
                hash: intent_hash.clone(),
                intent,
                status: status_str,
                solver: solver_str,
                solver_id: None, // TODO: Add solver ID lookup if needed
            };
            
            info!("✅ Found intent: {}", intent_hash);
            Ok(warp::reply::json(&response))
        }
        Ok(None) => {
            info!("❌ Intent not found: {}", intent_hash);
            Err(warp::reject::custom(TransactionError::NotFound))
        }
        Err(e) => {
            warn!("Failed to fetch intent {}: {}", intent_hash, e);
            Err(warp::reject::custom(TransactionError::DatabaseError))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentWithStatus {
    pub hash: String,
    pub intent: DepositIntent,
    pub status: String,
    pub solver: String,
    pub solver_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentListResponse {
    pub intents: Vec<IntentWithStatus>,
    pub count: usize,
}

async fn handle_get_intent_transaction_hash(
    intent_hash: String,
    db: std::sync::Arc<DatabaseManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🔍 Fetching transaction hash for intent: {}", intent_hash);
    
    // First check if there's an error for this intent
    let error_code = db.get_intent_error_code(&intent_hash).unwrap_or(None);
    let error_message = db.get_intent_error_message(&intent_hash).unwrap_or(None);
    let status = db.get_intent_status(&intent_hash).unwrap_or(Some("unknown".to_string())).unwrap_or("unknown".to_string());
    
    match db.get_intent_transaction_hash(&intent_hash) {
        Ok(Some(tx_hash)) => {
            info!("✅ Found transaction hash {} for intent {}", tx_hash, intent_hash);

            let response = serde_json::json!({
                "intent_hash": intent_hash,
                "transaction_hash": tx_hash,
                "status": "completed",
                "message": "Transaction completed successfully"
            });
            
            Ok(warp::reply::json(&response))
        }
        Ok(None) => {
            // No transaction hash found, check if there's an error
            if let (Some(code), Some(message)) = (error_code, error_message) {
                warn!("❌ Error found for intent {}: {} - {}", intent_hash, code, message);
                
                let response = serde_json::json!({
                    "intent_hash": intent_hash,
                    "transaction_hash": null,
                    "status": "failed",
                    "message": format!("Intent processing failed: {}", message),
                    "error_code": code,
                    "error_message": message
                });
                
                Ok(warp::reply::json(&response))
            } else {
            info!("❌ No transaction hash found for intent: {}", intent_hash);
            
            let response = serde_json::json!({
                "intent_hash": intent_hash,
                "transaction_hash": null,
                    "status": status,
                "message": "Transaction hash not yet available. Transaction may still be processing."
            });
            
            Ok(warp::reply::json(&response))
            }
        }
        Err(e) => {
            warn!("Failed to fetch transaction hash for intent {}: {}", intent_hash, e);
            Err(warp::reject::custom(TransactionError::DatabaseError))
        }
    }
}

#[derive(Debug)]
pub enum TransactionError {
    SerializationError,
    NetworkError,
    DatabaseError,
    NotFound,
}

impl warp::reject::Reject for TransactionError {}
