use crate::{
	rpc_server::{
		common::DummyTransaction,
		requests::{GetRewardSolverRequest, SolverRewardRequest},
		responses::{GetRewardSolverResponse, SolverRewardResponse},
		utils::{normalize_eth_signature, recover_eth_address_secp},
	},
	types::ChannelMessage,
	user_registry::checksum_from_any,
	DatabaseUserRegistry, DkgStorage,
};

use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub async fn handle_get_reward_solver(
	req: GetRewardSolverRequest,
	user_registry: std::sync::Arc<DatabaseUserRegistry>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("🔍 HTTP: get_reward_solver request for solver: {}", req.solver_address);

	// Validate solver_address
	if req.solver_address.trim().is_empty() {
		return Ok(warp::reply::json(&GetRewardSolverResponse {
			status: "error".to_string(),
			solver_address: req.solver_address,
			reward_btc: None,
			reward_tics: None,
			message: "Solver address cannot be empty".to_string(),
			error_message: Some("Solver address is required".to_string()),
		}));
	}

	// Validate Ethereum address format
	let normalized_address = match checksum_from_any(&req.solver_address) {
		Ok(addr) => addr,
		Err(e) => {
			warn!("❌ Invalid solver address format: {}", e);
			return Ok(warp::reply::json(&GetRewardSolverResponse {
				status: "error".to_string(),
				solver_address: req.solver_address,
				reward_btc: None,
				reward_tics: None,
				message: "Invalid solver address format".to_string(),
				error_message: Some(format!("Invalid address format: {}", e)),
			}));
		},
	};

	// Get solver rewards using user registry (both BTC and TICS)
	let reward_btc = user_registry.get_solver_reward_btc(&normalized_address).await;
	let reward_tics = user_registry.get_solver_reward_tics(&normalized_address).await;

	let reward_btc_str = reward_btc.as_ref().map(|v| v.to_string());
	let reward_tics_str = reward_tics.as_ref().map(|v| v.to_string());

	// For backward compatibility, keep `reward` as the sum if both exist, else whichever exists,
	// else 0
	let legacy_reward = match (reward_btc, reward_tics) {
		(Some(btc), Some(tics)) => (btc + tics).to_string(),
		(Some(btc), None) => btc.to_string(),
		(None, Some(tics)) => tics.to_string(),
		(None, None) => "0".to_string(),
	};

	info!(
		"✅ Rewards for solver {} -> btc: {:?}, tics: {:?}",
		normalized_address, reward_btc_str, reward_tics_str
	);

	Ok(warp::reply::json(&GetRewardSolverResponse {
		status: "success".to_string(),
		solver_address: normalized_address,
		reward_btc: reward_btc_str,
		reward_tics: reward_tics_str,
		message: "Solver rewards retrieved successfully".to_string(),
		error_message: None,
	}))
}
