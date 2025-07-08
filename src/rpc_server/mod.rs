use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest};
use tokio::sync::mpsc;
use tracing::{info, warn};
use warp::Filter;

use crate::types::{rpc::RPCRequest, ChannelMessage};

// Define the transaction types for the RPC server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyTransaction {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub data: Option<Vec<u8>>,
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
pub async fn start_http_server(message_tx: mpsc::Sender<ChannelMessage>, port: u16) -> Result<()> {
    let message_tx = std::sync::Arc::new(tokio::sync::Mutex::new(message_tx));

    // POST /submit_transaction
    let submit_tx = warp::path("submit_transaction")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_submit_transaction);

    // GET /status
    let get_status = warp::path("status")
        .and(warp::get())
        .and(with_message_tx(message_tx.clone()))
        .and_then(|message_tx| handle_get_status(message_tx));

    // POST /start_dkg
    let start_dkg = warp::path("start_dkg")
        .and(warp::post())
        .and(with_message_tx(message_tx))
        .and_then(|message_tx| handle_start_dkg(message_tx));

    let routes = submit_tx.or(get_status).or(start_dkg);

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

