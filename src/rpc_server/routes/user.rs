use crate::{
	rpc_server::{
		handlers::{handle_get_user_info, handle_register_user, handle_user_mpc_deposit},
		routes::{with_dkg_storage, with_message_tx, with_node_id, with_user_registry},
	},
	types::ChannelMessage,
	DatabaseUserRegistry, DkgStorage,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use warp::Filter;

pub fn user_routes(
	user_registry: Arc<DatabaseUserRegistry>,
	dkg_storage: Arc<DkgStorage>,
	message_tx: Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
	node_id: String,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
	let register_user = warp::path("register_user")
		.and(warp::post())
		.and(warp::body::json())
		.and(with_user_registry(user_registry.clone()))
		.and(with_dkg_storage(dkg_storage.clone()))
		.and(with_message_tx(message_tx.clone()))
		.and(with_node_id(node_id.clone()))
		.and_then(handle_register_user);

	let user_mpc_deposit = warp::path("user_mpc_deposit")
		.and(warp::post())
		.and(warp::body::json())
		.and(with_user_registry(user_registry.clone()))
		.and(with_message_tx(message_tx.clone()))
		.and(with_dkg_storage(dkg_storage.clone()))
		.and_then(handle_user_mpc_deposit);

	let get_user_info = warp::path("user_info")
		.and(warp::path::param())
		.and(warp::get())
		.and(with_user_registry(user_registry.clone()))
		.and_then(handle_get_user_info);

	register_user.or(user_mpc_deposit).or(get_user_info)
}
