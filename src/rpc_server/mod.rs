use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::sync::mpsc;
use tracing::{info, warn};
use warp::Filter;

use crate::database::DatabaseManager;
use crate::types::{rpc::RPCRequest, ChannelMessage, DepositIntent};

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
    
    let timeout_duration = std::time::Duration::from_secs(120); // 2 minutes timeout
    let poll_interval = std::time::Duration::from_millis(500); // Check every 500ms
    let start_time = std::time::Instant::now();

    loop {
        // Query transaction hash from signing node using round-based lookup
        if let Some(tx_hash) = query_transaction_hash_from_signing_node(&intent_hash, &message_tx).await {
            info!("🎯 Transaction hash retrieved for intent {}: {}", intent_hash, tx_hash);
            
            // Also query the solver ID (final node ID)
            let solver_id = query_final_node_from_signing_node(&intent_hash, &message_tx).await;
            info!("🏆 Solver ID retrieved for intent {}: {:?}", intent_hash, solver_id);
            
            let response = serde_json::json!({
                "intent_hash": intent_hash.clone(),
                "transaction_hash": tx_hash,
                "solver_id": solver_id,
                "status": "completed",
                "message": "Intent processed and transaction broadcasted successfully"
            });
            return Ok(warp::reply::json(&response));
        } else {
            // Hash not yet available, check if we've timed out
            if start_time.elapsed() >= timeout_duration {
                warn!("⏰ Timeout waiting for transaction hash for intent {}", intent_hash);
                
                // Still try to get the solver ID even on timeout
                let solver_id = query_final_node_from_signing_node(&intent_hash, &message_tx).await;
                
                let response = serde_json::json!({
                    "intent_hash": intent_hash.clone(),
                    "transaction_hash": null,
                    "solver_id": solver_id,
                    "status": "timeout",
                    "message": "Transaction processing timed out. Use the polling endpoint to check status.",
                    "polling_endpoint": format!("/intent/{}/transaction_hash", intent_hash)
                });
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
    
    match db.get_intent_transaction_hash(&intent_hash) {
        Ok(Some(tx_hash)) => {
            info!("✅ Found transaction hash {} for intent {}", tx_hash, intent_hash);

            let response = serde_json::json!({
                "intent_hash": intent_hash,
                "transaction_hash": tx_hash,
                "status": "found"
            });
            
            Ok(warp::reply::json(&response))
        }
        Ok(None) => {
            info!("❌ No transaction hash found for intent: {}", intent_hash);
            
            let response = serde_json::json!({
                "intent_hash": intent_hash,
                "transaction_hash": null,
                "status": "pending",
                "message": "Transaction hash not yet available. Transaction may still be processing."
            });
            
            Ok(warp::reply::json(&response))
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
