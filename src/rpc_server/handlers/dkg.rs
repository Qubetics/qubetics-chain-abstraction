use crate::{rpc_server::{errors::TransactionError, responses::{DKGStatusResponse, TransactionResponse}}, types::{rpc::RPCRequest, ChannelMessage}, DkgStorage};
use tracing::{info, warn};
use tokio::sync::mpsc;


pub async fn handle_get_dkg_status(
	dkg_storage: std::sync::Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("🔍 HTTP: Checking DKG status");

	let secret_share_available = match dkg_storage.get_final_secret().await {
		Ok(Some(_)) => true,
		Ok(None) => false,
		Err(e) => {
			warn!("Failed to read DKG secret share: {}", e);
			false
		},
	};
	let is_completed = secret_share_available;

	info!(
		"✅ HTTP: DKG status retrieved - completed: {}, secret_share_available: {}",
		is_completed, secret_share_available
	);

	Ok(warp::reply::json(&DKGStatusResponse {
		status: "success".to_string(),
		dkg_status: Some(if is_completed {
			"Completed".to_string()
		} else {
			"NotStarted".to_string()
		}),
		secret_share_available,
		message: if is_completed {
			"DKG completed successfully".to_string()
		} else {
			"DKG not completed yet".to_string()
		},
	}))
}


pub async fn handle_start_dkg(
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
		.send(ChannelMessage::Broadcast { topic: "dkg-commands".to_string(), data: dkg_data })
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

