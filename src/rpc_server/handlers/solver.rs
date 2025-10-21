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

pub async fn handle_solver_reward(
	req: SolverRewardRequest,
	user_registry: std::sync::Arc<DatabaseUserRegistry>,
	dkg_storage: std::sync::Arc<DkgStorage>,
	message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("🔍 HTTP: solver_reward request");

	let (compact, v) = match normalize_eth_signature(&req.signature) {
		Ok(t) => t,
		Err(e) => {
			warn!("❌ Invalid signature: {}", e);
			return Ok(warp::reply::json(&SolverRewardResponse {
				status: "error".to_string(),
				solver_address: "".to_string(),
				reward: None,
				error_message: Some(format!("Invalid signature: {}", e)),
			}));
		},
	};

	let msg_bytes = req.msg.as_bytes();
	let signer = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
		Ok(addr) => addr,
		Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
			Ok(addr) => addr,
			Err(e2) => {
				error!("❌ Failed to recover address: personal_sign={}, raw={}", e1, e2);
				return Ok(warp::reply::json(&SolverRewardResponse {
					status: "error".to_string(),
					solver_address: "".to_string(),
					reward: None,
					error_message: Some(format!(
						"Failed to recover signature: personal_sign={}, raw={}",
						e1, e2
					)),
				}));
			},
		},
	};

	let provided = match checksum_from_any(&req.address) {
		Ok(a) => a,
		Err(e) => {
			return Ok(warp::reply::json(&SolverRewardResponse {
				status: "error".to_string(),
				solver_address: signer,
				reward: None,
				error_message: Some(format!("Invalid address: {}", e)),
			}));
		},
	};

	if signer != provided {
		return Ok(warp::reply::json(&SolverRewardResponse {
			status: "error".to_string(),
			solver_address: signer,
			reward: None,
			error_message: Some("Recovered address does not match provided address".to_string()),
		}));
	}

	// Use user registry's reward storage instead of direct reward storage
	let reward_opt = user_registry.get_solver_reward_btc(&signer).await;
	let reward_str = reward_opt.as_ref().map(|r| r.to_string());

	if let Some(reward_u256) = reward_opt {
		let reward_u128 = reward_u256.as_u128();

		// Create dummy transaction representing solver reward
		let from_addr = match dkg_storage.get_final_public().await {
			Ok(Some(pk)) => crate::utils::get_eth_address_from_group_key(pk),
			_ => "0x0".to_string(),
		};

		let dummy_tx = DummyTransaction {
			to: signer.clone(),
			value: format!("0x{:x}", reward_u128),
			nonce: 0,
			gas_limit: 21_000,
			gas_price: "0x0".to_string(),
			chain_id: 1,
		};
		info!(
			"🧾 [HTTP] Created solver reward tx from {} to {} amount {}",
			from_addr, signer, reward_u128
		);

		let mut tx_sender = message_tx.lock().await;
		if let Err(e) = tx_sender
			.send(ChannelMessage::SolverReward {
				solver_address: signer.clone(),
				reward: reward_u128,
			})
			.await
		{
			warn!("Failed to send solver reward message: {}", e);
		}
	}
	Ok(warp::reply::json(&SolverRewardResponse {
		status: "success".to_string(),
		solver_address: signer,
		reward: reward_str,
		error_message: None,
	}))
}

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
