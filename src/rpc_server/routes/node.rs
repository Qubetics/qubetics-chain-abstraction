use crate::{
	rpc_server::{
		handlers::{handle_get_node_id, handle_get_status, handle_get_uptime, handle_heartbeat},
		routes::{with_message_tx, with_node_id, with_start_time},
	},
	types::ChannelMessage,
};
use std::{sync::Arc, time::Instant};
use tokio::sync::mpsc;
use warp::Filter;

pub fn node_routes(
	start_time: Arc<Instant>,
	node_id: String,
	message_tx: Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
	let with_node_id = || with_node_id(node_id.clone());
	let with_message_tx = || with_message_tx(message_tx.clone());
	let with_start_time = || with_start_time(start_time.clone());

	// GET /node_id
	let get_node_id = warp::path("node_id")
		.and(warp::get())
		.and(with_node_id())
		.and_then(handle_get_node_id);

	// GET /status
	let get_status = warp::path("status")
		.and(warp::get())
		.and(with_message_tx())
		.and_then(handle_get_status);

	// GET /heartbeat
	let heartbeat = warp::path("heartbeat").and(warp::get()).and_then(handle_heartbeat);

	// GET /uptime
	let uptime = warp::path("uptime")
		.and(warp::get())
		.and(with_start_time())
		.and_then(handle_get_uptime);

	get_node_id.or(get_status).or(heartbeat).or(uptime)
}
