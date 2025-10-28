use crate::{
	database::{DkgStorage, RewardStorage},
	rpc_server::{middleware::cors::cors_filter, routes::api_routes},
	types::ChannelMessage,
	user_registry::DatabaseUserRegistry,
};

use std::{sync::Arc, time::Instant};
use tokio::sync::mpsc;
use tracing::info;
use warp::Filter;

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

	let api =
		api_routes(message_tx, user_registry, dkg_storage, reward_storage, node_id, start_time);

	info!("🌐 Starting HTTP RPC server on port {}", port);
	let cors = cors_filter();

	warp::serve(api.with(cors)).run(([0, 0, 0, 0], port)).await;
	Ok(())
}
