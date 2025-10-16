use crate::{
	rpc_server::{
		common::DummyTransaction, errors::TransactionError, responses::{NodeIdResponse, NodeStatusResponse, TransactionResponse}, types::responses::{HeartbeatResponse, UptimeResponse}
	},
	types::ChannelMessage,
};
use tokio::sync::mpsc;
use tracing::{info, warn};
use sha2::Digest;

pub async fn handle_heartbeat() -> Result<impl warp::Reply, warp::Rejection> {
	Ok(warp::reply::json(&HeartbeatResponse { status: "alive".to_string() }))
}

pub async fn handle_get_uptime(
	start_time: std::sync::Arc<std::time::Instant>,
) -> Result<impl warp::Reply, warp::Rejection> {
	let uptime = start_time.elapsed().as_secs();
	Ok(warp::reply::json(&UptimeResponse { uptime_seconds: uptime }))
}

pub async fn handle_get_node_id(node_id: String) -> Result<impl warp::Reply, warp::Rejection> {
	Ok(warp::reply::json(&NodeIdResponse { node_id }))
}

pub async fn handle_get_status(
	_message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("here at handle status!! ");
	Ok(warp::reply::json(&NodeStatusResponse {
		peer_id: "dummy-peer-id".to_string(),
		connected_peers: 0,
		dkg_status: "unknown".to_string(),
		is_ready: true,
	}))
}


pub async fn handle_submit_transaction(
	tx: DummyTransaction,
	message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("📝 HTTP: Received transaction: {:?}", tx);

	let tx_hash = format!("0x{:x}", sha2::Sha256::digest(format!("{:?}", tx).as_bytes()));

	// First, process the transaction locally (this node will sign it)
	info!("🔐 [LOCAL] Processing transaction locally for signing");

	// Send a special local processing message
	let local_msg = ChannelMessage::LocalTransaction { transaction: tx.clone() };

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
		.send(ChannelMessage::Broadcast { topic: "transactions".to_string(), data: tx_data })
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

