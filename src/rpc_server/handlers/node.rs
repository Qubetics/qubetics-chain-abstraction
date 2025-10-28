use crate::{
	rpc_server::{
		common::DummyTransaction,
		errors::TransactionError,
		responses::{NodeIdResponse, NodeStatusResponse, TransactionResponse},
		types::responses::{HeartbeatResponse, UptimeResponse},
	},
	types::ChannelMessage,
};
use sha2::Digest;
use tokio::sync::mpsc;
use tracing::{info, warn};

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
