use crate::{
	rpc_server::{
		common::DummyTransaction,
		requests::{ClaimRewardRequest, GetRewardSolverRequest, SolverRewardRequest},
		responses::{ClaimRewardResponse, GetRewardSolverResponse, SolverRewardResponse},
		utils::{normalize_eth_signature, recover_eth_address_secp, validate_ethereum_address},
	},
	types::ChannelMessage,
	user_registry::checksum_from_any,
	DatabaseUserRegistry, DkgStorage, RewardStorage,
};

use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub async fn handle_claim_reward(
	req: ClaimRewardRequest,
	user_registry: std::sync::Arc<DatabaseUserRegistry>,
	reward_storage: std::sync::Arc<RewardStorage>,
	message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!(
		"🎁 HTTP: claim_reward request for ETH: {:?}, BTC: {:?}",
		req.ethereum_address, req.btc_address
	);

	// Validate that at least one address is provided
	if req.ethereum_address.is_none() && req.btc_address.is_none() {
		warn!("❌ Both addresses are None - at least one address must be provided");
		return Ok(warp::reply::json(&ClaimRewardResponse {
			status: "error".to_string(),
			ethereum_address: None,
			btc_address: None,
			reward_btc: None,
			reward_tics: None,
			total_reward: None,
			message: "At least one address must be provided".to_string(),
			error_message: Some("Both ethereum_address and btc_address cannot be None".to_string()),
		}));
	}

	// Validate Ethereum address format if provided
	let normalized_eth_address = if let Some(eth_addr) = &req.ethereum_address {
		match validate_ethereum_address(eth_addr) {
			Ok(addr) => Some(addr),
			Err(e) => {
				warn!("❌ Invalid Ethereum address format: {:?}", e);
				return Ok(warp::reply::json(&ClaimRewardResponse {
					status: "error".to_string(),
					ethereum_address: req.ethereum_address,
					btc_address: req.btc_address,
					reward_btc: None,
					reward_tics: None,
					total_reward: None,
					message: "Invalid Ethereum address format".to_string(),
					error_message: Some(format!("Invalid Ethereum address: {:?}", e)),
				}));
			},
		}
	} else {
		None
	};

	// Validate signature format
	let (compact, v) = match normalize_eth_signature(&req.signature) {
		Ok(t) => t,
		Err(e) => {
			warn!("❌ Invalid signature format: {}", e);
			return Ok(warp::reply::json(&ClaimRewardResponse {
				status: "error".to_string(),
				ethereum_address: normalized_eth_address,
				btc_address: req.btc_address,
				reward_btc: None,
				reward_tics: None,
				total_reward: None,
				message: "Invalid signature format".to_string(),
				error_message: Some(format!("Invalid signature: {:?}", e)),
			}));
		},
	};

	// Recover signer address from signature
	let msg_bytes = req.message.as_bytes();
	let signer_address = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
		Ok(addr) => addr,
		Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
			Ok(addr) => addr,
			Err(e2) => {
				error!("❌ Failed to recover address: personal_sign={}, raw={}", e1, e2);
				return Ok(warp::reply::json(&ClaimRewardResponse {
					status: "error".to_string(),
					ethereum_address: normalized_eth_address,
					btc_address: req.btc_address,
					reward_btc: None,
					reward_tics: None,
					total_reward: None,
					message: "Failed to recover signature".to_string(),
					error_message: Some(format!(
						"Failed to recover signature: personal_sign={}, raw={}",
						e1, e2
					)),
				}));
			},
		},
	};

	// Verify that the recovered address matches the provided Ethereum address (if provided)
	if let Some(ref eth_addr) = normalized_eth_address {
		if signer_address != *eth_addr {
			warn!(
				"❌ Signature verification failed: recovered {} != provided {}",
				signer_address, eth_addr
			);
			return Ok(warp::reply::json(&ClaimRewardResponse {
				status: "error".to_string(),
				ethereum_address: normalized_eth_address,
				btc_address: req.btc_address,
				reward_btc: None,
				reward_tics: None,
				total_reward: None,
				message: "Signature verification failed".to_string(),
				error_message: Some(
					"Recovered address does not match provided Ethereum address".to_string(),
				),
			}));
		}
	}


	let reward_btc = user_registry.get_solver_reward_btc(&signer_address).await;
	let reward_tics = user_registry.get_solver_reward_tics(&signer_address).await;

    // Check if the signer has any rewards to claim
    if reward_btc.is_none() && reward_tics.is_none() {
        warn!("❌ Signer {} is not a registered solver or has no rewards available", signer_address);
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: normalized_eth_address,
            btc_address: req.btc_address,
            reward_btc: None,
            reward_tics: None,
            total_reward: None,
            message: "Signer is not a registered solver or has no rewards".to_string(),
            error_message: Some(format!("Address {} has no rewards available", signer_address)),
        }));
    }


	let reward_btc_str = reward_btc.as_ref().map(|v| v.to_string());
	let reward_tics_str = reward_tics.as_ref().map(|v| v.to_string());

	// Calculate total reward
	let total_reward = match (reward_btc, reward_tics) {
		(Some(btc), Some(tics)) => Some((btc + tics).to_string()),
		(Some(btc), None) => Some(btc.to_string()),
		(None, Some(tics)) => Some(tics.to_string()),
		(None, None) => None,
	};


	// If there are rewards, send a claim message to the network
	let claim_msg = ChannelMessage::ClaimReward {
		solver_address: signer_address.clone(), // the solver who is claiming
		btc_address: req.btc_address.clone(),
		eth_address: req.ethereum_address.clone(),
		reward_btc: reward_btc_str.clone(),
		reward_tics: reward_tics_str.clone(),
	};

	let mut tx_sender = message_tx.lock().await;
	if let Err(e) = tx_sender.send(claim_msg).await {
		warn!("Failed to send claim reward message: {}", e);
		return Ok(warp::reply::json(&ClaimRewardResponse {
			status: "error".to_string(),
			ethereum_address: normalized_eth_address,
			btc_address: req.btc_address,
			reward_btc: reward_btc_str,
			reward_tics: reward_tics_str,
			total_reward,
			message: "Failed to process reward claim".to_string(),
			error_message: Some(format!("Network error: {}", e)),
		}));
	}

	info!(
		"✅ Reward claim processed successfully for solver: {}, BTC: {:?}",
		signer_address, req.btc_address
	);

	Ok(warp::reply::json(&ClaimRewardResponse {
		status: "success".to_string(),
		ethereum_address: normalized_eth_address,
		btc_address: req.btc_address,
		reward_btc: reward_btc_str,
		reward_tics: reward_tics_str,
		total_reward,
		message: "Reward claim processed successfully".to_string(),
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
