use crate::{
	rpc_server::{
		handlers::{handle_get_dkg_status, handle_start_dkg},
		routes::{with_dkg_storage, with_message_tx},
	},
	types::ChannelMessage,
	DkgStorage,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use warp::Filter;

pub fn dkg_routes(
	dkg_storage: Arc<DkgStorage>,
	message_tx: Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
	let get_dkg_status = warp::path("dkg_status")
		.and(warp::get())
		.and(with_dkg_storage(dkg_storage.clone()))
		.and_then(handle_get_dkg_status);

	let start_dkg = warp::path("start_dkg")
		.and(warp::post())
		.and(with_message_tx(message_tx.clone()))
		.and_then(handle_start_dkg);

	get_dkg_status.or(start_dkg)
}
