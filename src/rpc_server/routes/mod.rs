use crate::{
	rpc_server::routes::node::node_routes, types::ChannelMessage, DatabaseUserRegistry, DkgStorage,
	RewardStorage,
};
use std::{sync::Arc, time::Instant};
use tokio::sync::mpsc;
use warp::Filter;

mod dkg;
mod node;
mod solver;
mod user;

pub fn api_routes(
	message_tx: Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
	user_registry: Arc<DatabaseUserRegistry>,
	dkg_storage: Arc<DkgStorage>,
	reward_storage: Arc<RewardStorage>,
	node_id: String,
	start_time: Arc<Instant>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
	node_routes(start_time, node_id.clone(), message_tx.clone())
		.or(user::user_routes(
			user_registry.clone(),
			dkg_storage.clone(),
			message_tx.clone(),
			node_id.clone(),
		))
		.or(dkg::dkg_routes(dkg_storage.clone(), message_tx.clone()))
		.or(solver::solver_routes(user_registry.clone(), dkg_storage.clone(), message_tx.clone()))
}

// Helper functions for injecting state into warp filters (moved from server.rs)

pub fn with_message_tx(
	message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> impl Filter<
	Extract = (std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,),
	Error = std::convert::Infallible,
> + Clone {
	warp::any().map(move || message_tx.clone())
}

pub fn with_user_registry(
	user_registry: std::sync::Arc<DatabaseUserRegistry>,
) -> impl Filter<Extract = (std::sync::Arc<DatabaseUserRegistry>,), Error = std::convert::Infallible>
       + Clone {
	warp::any().map(move || user_registry.clone())
}

pub fn with_dkg_storage(
	dkg_storage: std::sync::Arc<DkgStorage>,
) -> impl Filter<Extract = (std::sync::Arc<DkgStorage>,), Error = std::convert::Infallible> + Clone
{
	warp::any().map(move || dkg_storage.clone())
}

pub fn with_reward_storage(
	reward_storage: std::sync::Arc<RewardStorage>,
) -> impl Filter<Extract = (std::sync::Arc<RewardStorage>,), Error = std::convert::Infallible> + Clone
{
	warp::any().map(move || reward_storage.clone())
}

pub fn with_node_id(
	node_id: String,
) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
	warp::any().map(move || node_id.clone())
}

pub fn with_start_time(
	start_time: std::sync::Arc<std::time::Instant>,
) -> impl Filter<Extract = (std::sync::Arc<std::time::Instant>,), Error = std::convert::Infallible> + Clone
{
	warp::any().map(move || start_time.clone())
}
