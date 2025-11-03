use crate::{
	rpc_server::{
		handlers::handle_get_reward_solver,
		requests::GetRewardSolverRequest,
		routes::{with_dkg_storage, with_message_tx, with_reward_storage, with_user_registry},
	},
	types::ChannelMessage,
	DatabaseUserRegistry, DkgStorage, RewardStorage,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use warp::Filter;

pub fn solver_routes(
	user_registry: Arc<DatabaseUserRegistry>,
	dkg_storage: Arc<DkgStorage>,
	reward_storage: Arc<RewardStorage>,
	message_tx: Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
	// let solver_reward = warp::path("solver_reward")
	// 	.and(warp::post())
	// 	.and(warp::body::json())
	// 	.and(with_user_registry(user_registry.clone()))
	// 	.and(with_dkg_storage(dkg_storage.clone()))
	// 	.and(with_message_tx(message_tx.clone()))
	// 	.and_then(handle_solver_reward);

	// let claim_reward = warp::path("claim_reward")
	// 	.and(warp::post())
	// 	.and(warp::body::json())
	// 	.and(with_user_registry(user_registry.clone()))
	// 	.and(with_reward_storage(reward_storage.clone()))
	// 	.and(with_message_tx(message_tx.clone()))
	// 	.and_then(handle_claim_reward);

	let get_reward_solver = warp::path("get_reward_solver")
		.and(warp::get())
		.and(warp::query::<GetRewardSolverRequest>())
		.and(with_user_registry(user_registry.clone()))
		.and_then(handle_get_reward_solver);

	get_reward_solver
}
