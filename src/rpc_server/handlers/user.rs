use crate::{
	rpc_server::{
		common::DepositIntent,
		errors::{RpcError, TransactionError},
		requests::{UserMpcDepositRequest, UserRegistrationRequest},
		responses::{
			DepositIntentResponse, EnhancedUserRegistrationResponse, UserInfoResponse,
			UserMpcDepositVerifyResponse,
		},
		services::fetch_crypto_prices,
		utils::{
			convert_src_smallest_to_dst_smallest, get_actual_dkg_secret_share,
			normalize_eth_signature, recover_eth_address_secp, validate_ethereum_address,
			wait_for_transaction_result,
		},
	},
	types::ChannelMessage,
	DatabaseUserRegistry, DkgStorage,
};
use sha2::Digest;
use sha3::Keccak256;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

pub async fn handle_register_user(
	request: UserRegistrationRequest,
	user_registry: std::sync::Arc<DatabaseUserRegistry>,
	dkg_storage: std::sync::Arc<DkgStorage>,
	message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
	node_id: String,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("👤 HTTP: Received user registration request for address: {}", request.ethereum_address);

	// Input validation
	let addr_cs = match validate_ethereum_address(&request.ethereum_address) {
		Ok(normalized) => normalized,
		Err(e) => {
			error!(
				"❌ HTTP: Address validation failed for '{}': {:?}",
				request.ethereum_address, e
			);
			let error_response = EnhancedUserRegistrationResponse {
				status: "error".to_string(),
				message: "Invalid Ethereum address".to_string(),
				derived_eth_address: None,
				derived_btc_address: None,
				error: Some(e.to_error_response()),
			};
			return Ok(warp::reply::json(&error_response));
		},
	};

	// Check if user is already registered
	if let Some(_existing_user) = user_registry.get_user_by_address(&addr_cs).await {
		info!("⚠️ HTTP: User already registered: {}", addr_cs);
		let error_response = EnhancedUserRegistrationResponse {
			status: "error".to_string(),
			message: "User is already registered".to_string(),
			derived_eth_address: None,
			derived_btc_address: None,
			error: Some(
				RpcError::InvalidRequest("User is already registered".to_string())
					.to_error_response(),
			),
		};
		return Ok(warp::reply::json(&error_response));
	}

	// Check DKG status
	let dkg_secret_share = get_actual_dkg_secret_share(dkg_storage).await;
	if dkg_secret_share.is_none() {
		warn!("⚠️ HTTP: DKG not ready for user registration");
		let error_response = EnhancedUserRegistrationResponse {
			status: "error".to_string(),
			message: "DKG system is not ready. Please try again later.".to_string(),
			derived_eth_address: None,
			derived_btc_address: None,
			error: Some(
				RpcError::DkgNotReady("DKG secret share not available".to_string())
					.to_error_response(),
			),
		};
		return Ok(warp::reply::json(&error_response));
	}

	// Attempt user registration
	match user_registry.register_user(&addr_cs, dkg_secret_share.as_ref(), &node_id).await {
		Ok(registration) => {
			info!("✅ HTTP: User registration successful for address: {}", addr_cs);

			// Log tweaked secret share status
			if registration.tweaked_secret_share.is_some() {
				info!("🔑 HTTP: Computed and stored tweaked secret share for user: {}", addr_cs);
			} else {
				warn!("⚠️ HTTP: No tweaked secret share computed for user: {}", addr_cs);
			}

			// Broadcast to other nodes via P2P network
			let user_reg_msg = ChannelMessage::UserRegistration {
				ethereum_address: addr_cs.clone(),
				node_id: node_id.to_string(),
			};

			// Send via message channel to be picked up by network layer
			if let Ok(tx) = message_tx.try_lock() {
				if let Err(e) = tx.send(user_reg_msg).await {
					error!("❌ Failed to send user registration message to network: {}", e);
					// Don't fail registration if broadcasting fails
					warn!("⚠️ User registered locally but network broadcast failed");
				} else {
					info!("📡 User registration message sent to network layer for broadcasting");
				}
			} else {
				warn!("⚠️ Could not acquire message channel lock for network broadcast");
			}

			// Wait for derived addresses to be populated
			info!("⏳ Waiting for derived addresses to be populated...");
			let mut attempts = 0;
			const MAX_ATTEMPTS: u8 = 10; // Wait up to 10 seconds

			let mut final_registration = registration.clone();
			while attempts < MAX_ATTEMPTS {
				// Check if derived addresses are now available
				match user_registry.get_user_by_address(&addr_cs).await {
					Some(updated_user) =>
						if updated_user.derived_eth_address.is_some() &&
							updated_user.derived_btc_address.is_some()
						{
							final_registration = updated_user;
							info!("✅ Derived addresses are now available!");
							break;
						},
					None => {
						error!("❌ User disappeared from registry during address derivation");
						break;
					},
				}

				attempts += 1;
				if attempts < MAX_ATTEMPTS {
					info!(
						"⏳ Attempt {}/{}: Derived addresses not ready yet, waiting 1 second...",
						attempts, MAX_ATTEMPTS
					);
					tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
				}
			}

			if attempts >= MAX_ATTEMPTS {
				warn!("⚠️ Derived addresses not available after {} attempts", MAX_ATTEMPTS);
			}

			// Log derived addresses if available
			if let Some(eth_addr) = &final_registration.derived_eth_address {
				info!("📬 HTTP: Derived ETH address for {}: {}", addr_cs, eth_addr);
			}
			if let Some(btc_addr) = &final_registration.derived_btc_address {
				info!("📬 HTTP: Derived BTC address for {}: {}", addr_cs, btc_addr);
			}

			// Successful response
			let response = EnhancedUserRegistrationResponse {
				status: "success".to_string(),
				message: "User registered successfully".to_string(),
				derived_eth_address: final_registration.derived_eth_address,
				derived_btc_address: final_registration.derived_btc_address,
				error: None,
			};

			Ok(warp::reply::json(&response))
		},
		Err(e) => {
			error!("❌ HTTP: User registration failed for address {}: {}", addr_cs, e);

			let error_response = EnhancedUserRegistrationResponse {
				status: "error".to_string(),
				message: "User registration failed".to_string(),
				derived_eth_address: None,
				derived_btc_address: None,
				error: Some(RpcError::RegistrationFailed(e.to_string()).to_error_response()),
			};

			Ok(warp::reply::json(&error_response))
		},
	}
}

pub async fn handle_get_user_info(
	ethereum_address: String,
	user_registry: std::sync::Arc<DatabaseUserRegistry>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("🔍 HTTP: Received user info request for address: {}", ethereum_address);

	// Input validation
	let addr_cs = match validate_ethereum_address(&ethereum_address) {
		Ok(normalized) => normalized,
		Err(e) => {
			error!("❌ HTTP: Address validation failed for '{}': {:?}", ethereum_address, e);
			let error_response = UserInfoResponse {
				status: "error".to_string(),
				user_id: None,
				ethereum_address: None,
				hmac_constant: None,
				has_tweaked_share: None,
				has_user_group_key: None,
				derived_eth_address: None,
				derived_btc_address: None,
				created_at: None,
				error: Some(e.to_error_response()),
			};
			return Ok(warp::reply::json(&error_response));
		},
	};

	info!("🔍 HTTP: Looking up user info for (normalized): {}", addr_cs);

	// Database operation with error handling
	match user_registry.get_user_by_address(&addr_cs).await {
		Some(registration) => {
			info!("✅ HTTP: Found user info for {}", addr_cs);

			// Successful response
			let response = UserInfoResponse {
				status: "success".to_string(),
				user_id: Some(registration.user_id),
				ethereum_address: Some(registration.ethereum_address),
				hmac_constant: Some(hex::encode(registration.hmac_constant)),
				has_tweaked_share: Some(registration.tweaked_secret_share.is_some()),
				has_user_group_key: Some(registration.user_group_key.is_some()),
				derived_eth_address: registration.derived_eth_address,
				derived_btc_address: registration.derived_btc_address,
				created_at: Some(registration.created_at.to_rfc3339()),
				error: None,
			};

			Ok(warp::reply::json(&response))
		},
		None => {
			info!("❌ HTTP: User not found for {}", addr_cs);

			// User not found response
			let error_response = UserInfoResponse {
				status: "error".to_string(),
				user_id: None,
				ethereum_address: None,
				hmac_constant: None,
				has_tweaked_share: None,
				has_user_group_key: None,
				derived_eth_address: None,
				derived_btc_address: None,
				created_at: None,
				error: Some(
					RpcError::UserNotFound(format!("User with address {} not found", addr_cs))
						.to_error_response(),
				),
			};

			Ok(warp::reply::json(&error_response))
		},
	}
}

pub async fn handle_user_mpc_deposit(
	req: UserMpcDepositRequest,
	user_registry: std::sync::Arc<DatabaseUserRegistry>,
	message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
	dkg_storage: std::sync::Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("🧾 HTTP: user_mpc_deposit: amount={}", req.msg.amount);
	// If transaction ID and status are provided, update the database accordingly

	// Serialize the DepositIntent to match the client's JSON.stringify() format
	// Use compact JSON serialization (no spaces) to match JavaScript's JSON.stringify()
	let intent_json = serde_json::to_string(&req.msg).unwrap();
	let intent_bytes = intent_json.as_bytes();
	let intent_hash = Keccak256::digest(intent_bytes);
	let intent_hash_hex = hex::encode(intent_hash);

	let mut transaction_ids = Vec::new();

	let tx_mapping = user_registry.get_intent_transaction_ids(&intent_hash_hex).await;
	if let Some(tx_ids) = user_registry.get_intent_transaction_ids(&intent_hash_hex).await {
		// Only store transaction IDs if there's no error
		if tx_ids.error_message.is_none() {
			if let Some(ref user_to_network_tx) = tx_ids.user_to_network_tx_id {
				transaction_ids.push(user_to_network_tx.clone());
			}
			if let Some(ref network_to_target_tx) = tx_ids.network_to_target_tx_id {
				transaction_ids.push(network_to_target_tx.clone());
			}
		}
	}
	// Process the deposit intent
	// If there are any transaction IDs, req.tx_id must be provided, else return error
	// if transaction_ids.len() >= 1 && req.tx_id.is_none() {
	//     return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
	//         status: "error".to_string(),
	//         signer_address: "".to_string(),
	//         is_registered: false,
	//         amount: 0,
	//         user_to_network_tx_id: None,
	//         network_to_target_tx_id: None,
	//         vault_to_network_tx_id: None,
	//         error_message: Some(
	//             "Transaction ID must be provided when transaction(s) already exist for this
	// intent"                 .to_string(),
	//         ),
	//     }));
	// }

	let transaction_type = if transaction_ids.len() == 1 {
		crate::types::TransactionType::NetworkToTarget
	} else if transaction_ids.len() == 0 {
		crate::types::TransactionType::UserToVault
	} else {
		// More than 2 transactions indicates a duplicate intent
		return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
			status: "error".to_string(),
			signer_address: "".to_string(),
			is_registered: false,
			amount: 0,
			user_to_network_tx_id: tx_mapping
				.as_ref()
				.and_then(|tx| tx.user_to_network_tx_id.clone()),
			network_to_target_tx_id: tx_mapping
				.as_ref()
				.and_then(|tx| tx.network_to_target_tx_id.clone()),
			vault_to_network_tx_id: None,
			final_solver_id: None,
			error_message: Some(
				"Duplicate intent detected - this intent has already been processed".to_string(),
			),
		}));
	};

	// if let Some(ref tx_id) = req.tx_id {
	//     if let Some(status) = user_registry.get_transaction_status(tx_id).await {
	//         if status == TransactionStatus::Confirmed {
	//             warn!(
	//                 "❌ Transaction {} is already confirmed, rejecting duplicate call",
	//                 tx_id
	//             );
	//             return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
	//                 status: "error".to_string(),
	//                 signer_address: "".to_string(),
	//                 is_registered: false,
	//                 amount: 0,
	//                 user_to_network_tx_id: None,
	//                 network_to_target_tx_id: None,
	//                 vault_to_network_tx_id: None,
	//                 error_message: Some(format!(
	//                     "Transaction {} is already confirmed and cannot be processed again",
	//                     tx_id
	//                 )),
	//             }));
	//         }
	//     }
	// }

	info!("🔐 Processing MPC deposit - Intent hash: {:?}, Amount: {}", intent_hash, req.msg.amount);
	info!("📝 Server JSON serialization: {}", intent_json);
	info!(
		"📏 JSON length: {}, First 100 chars: {}",
		intent_json.len(),
		if intent_json.len() > 100 { &intent_json[0..100] } else { &intent_json }
	);
	// Check if the intent hash is already stored; if yes, retrieve user details in a variable
	// Retrieve the user by intent hash and immediately handle Some/None
	let user_registration = match user_registry.get_user_by_intent_hash(&intent_hash_hex).await {
		Some(existing_user) => existing_user,
		None => {
			// No existing user for this intent hash
			match &req.signature {
				Some(signature) => {
					info!("No existing user found for intent hash, but signature is present in the request.");
					let (compact, v) = match normalize_eth_signature(signature) {
						Ok(t) => t,
						Err(e) => {
							warn!("❌ Failed to normalize signature: {}", e);
							return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
								status: "error".to_string(),
								signer_address: "".to_string(),
								is_registered: false,
								amount: 0,
								user_to_network_tx_id: None,
								network_to_target_tx_id: None,
								vault_to_network_tx_id: None,
								final_solver_id: None,
								error_message: Some(format!("Invalid signature format: {}", e)),
							}));
						},
					};
					let (signer, _used_personal) =
						match recover_eth_address_secp(intent_bytes, &compact, v, true) {
							Ok(addr) => (addr, true),
							Err(e1) => {
								warn!("⚠️ personal_sign recovery failed: {}", e1);
								match recover_eth_address_secp(intent_bytes, &compact, v, false) {
									Ok(addr) => (addr, false),
									Err(e2) => {
										error!("❌ Both signature recovery methods failed: personal_sign={}, raw={}", e1, e2);
										return Ok(warp::reply::json(
											&UserMpcDepositVerifyResponse {
												status: "error".to_string(),
												signer_address: "".to_string(),
												is_registered: false,
												amount: 0,
												user_to_network_tx_id: None,
												network_to_target_tx_id: None,
												vault_to_network_tx_id: None,
												final_solver_id: None,
												error_message: Some(format!(
											"Failed to recover signature: personal_sign={}, raw={}",
											e1, e2
										)),
											},
										));
									},
								}
							},
						};
					// Fetch UserRegistration from signer address first
					let user_reg = match user_registry.get_user_by_address(&signer).await {
						Some(user_reg) => user_reg,
						None => {
							return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
								status: "error".to_string(),
								signer_address: signer.clone(),
								is_registered: false,
								amount: 0,
								user_to_network_tx_id: None,
								network_to_target_tx_id: None,
								vault_to_network_tx_id: None,
								final_solver_id: None,
								error_message: Some(
									"No user registration found for signer address.".to_string(),
								),
							}));
						},
					};
					// Fetch balance of derived address based on source_chain
					// Add 10% buffer to the minimum required amount
					let min_amount = req.msg.amount + (req.msg.amount / 10);
					let source_chain = req.msg.source_chain.to_lowercase();
					let mut address_to_check = String::new();
					let mut blockchain = String::new();

					if source_chain == "qubetics" {
						// Use eth_derived address from user_reg details
						if let Some(eth_addr) = &user_reg.derived_eth_address {
							address_to_check = eth_addr.clone();
							// Ensure 0x prefix
							if !address_to_check.starts_with("0x") {
								address_to_check = format!("0x{}", address_to_check);
							}
						} else {
							return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
								status: "error".to_string(),
								signer_address: signer.clone(),
								is_registered: true,
								amount: 0,
								user_to_network_tx_id: None,
								network_to_target_tx_id: None,
								vault_to_network_tx_id: None,
								final_solver_id: None,
								error_message: Some(
									"No eth_derived address found for user.".to_string(),
								),
							}));
						}
						blockchain = "eth".to_string();
					} else if source_chain == "bitcoin" {
						// Use btc_derived address from user_reg details
						if let Some(btc_addr) = &user_reg.derived_btc_address {
							address_to_check = btc_addr.clone();
						} else {
							return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
								status: "error".to_string(),
								signer_address: signer.clone(),
								is_registered: true,
								amount: 0,
								user_to_network_tx_id: None,
								network_to_target_tx_id: None,
								vault_to_network_tx_id: None,
								final_solver_id: None,
								error_message: Some(
									"No btc_derived address found for user.".to_string(),
								),
							}));
						}
						blockchain = "btc".to_string();
					} else {
						return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
							status: "error".to_string(),
							signer_address: signer.clone(),
							is_registered: true,
							amount: 0,
							user_to_network_tx_id: None,
							network_to_target_tx_id: None,
							vault_to_network_tx_id: None,
							final_solver_id: None,
							error_message: Some(format!(
								"Unsupported source chain: {}",
								source_chain
							)),
						}));
					}
					// let balance = match fetch_balance(&address_to_check, &blockchain).await {
					//     Ok(b) => b,
					//     Err(e) => {
					//         return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
					//             status: "error".to_string(),
					//             signer_address: signer.clone(),
					//             is_registered: true,
					//             amount: 0,
					//             user_to_network_tx_id: None,
					//             network_to_target_tx_id: None,
					//             vault_to_network_tx_id: None,
					//             error_message: Some(e),
					//         }));
					//     }
					// };
					// if balance < min_amount {
					//     return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
					//         status: "error".to_string(),
					//         signer_address: signer.clone(),
					//         is_registered: true,
					//         amount: balance,
					//         user_to_network_tx_id: None,
					//         network_to_target_tx_id: None,
					//         vault_to_network_tx_id: None,
					//         error_message: Some(format!(
					//             "Insufficient balance: required {}, found {}",
					//             min_amount, balance
					//         )),
					//     }));
					// }
					// Store intent hash via network channel and broadcast
					let intent_hash_bytes = intent_hash.to_vec();
					let store_msg = ChannelMessage::IntentHash {
						intent_hash: intent_hash_bytes.clone(),
						signer: signer.clone(),
						intent: req.msg.clone(),
					};
					let tx_sender = message_tx.lock().await;
					if let Err(e) = tx_sender.send(store_msg).await {
						error!("❌ Failed to dispatch intent hash store message: {}", e);
						return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
							status: "error".to_string(),
							signer_address: signer.clone(),
							is_registered: true,
							amount: 0,
							user_to_network_tx_id: None,
							network_to_target_tx_id: None,
							vault_to_network_tx_id: None,
							final_solver_id: None,
							error_message: Some(format!("Failed to process deposit intent: {}", e)),
						}));
					}

					info!("✅ Intent hash store message sent for user: {}", signer);

					user_reg
				},
				None => {
					// No signature provided and no details found in DB, return error
					return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
						status: "error".to_string(),
						signer_address: "".to_string(),
						is_registered: false,
						amount: 0,
						user_to_network_tx_id: None,
						network_to_target_tx_id: None,
						vault_to_network_tx_id: None,
						final_solver_id: None,
						error_message: Some("No details found in database for intent hash and no signature provided.".to_string()),
					}));
				},
			}
		},
	};

	let user_eth_address = match transaction_type {
		crate::types::TransactionType::UserToVault =>
			Some(user_registration.ethereum_address.clone()),
		_ => None,
	};
	// Fetch all transaction IDs corresponding to this intent hash
	let intent_hash_hex = hex::encode(&intent_hash);

	let chain_to_check = if let Some(ref tx_id) = req.tx_id {
		if let Some(ref map) = tx_mapping {
			if map.user_to_network_tx_id.as_ref() == Some(tx_id) {
				Some("source")
			} else if map.network_to_target_tx_id.as_ref() == Some(tx_id) {
				Some("target")
			} else {
				Some("tics")
			}
		} else {
			None
		}
	} else {
		None
	};

	// Only perform this check if a tx_id is provided
	if let Some(ref tx_id) = req.tx_id {
		// Determine which chain to check based on mapping logic
		let source_chain = req.msg.source_chain.to_lowercase();
		let target_chain = req.msg.target_chain.to_lowercase();
		let selected_chain = match chain_to_check {
			Some("target") => &target_chain,
			Some("source") => &source_chain,
			// If chain_to_check is "tics" or any other value, always use "tics"
			Some("tics") | Some(_) => "tics",
			None => "tics", // Defensive, but should not happen if tx_id is Some
		};

		// match check_tx_confirmation(selected_chain, tx_id).await {
		//     Ok(true) => {
		//         // Only update the status in db if txn is confirmed
		//         if let Err(e) = user_registry
		//             .update_transaction_status(tx_id, TransactionStatus::Confirmed)
		//             .await
		//         {
		//             error!("Failed to update transaction status in db: {}", e);
		//         } else {
		//             info!(
		//                 "✅ Updated transaction status in db for {}: {:?}",
		//                 tx_id,
		//                 TransactionStatus::Confirmed
		//             );
		//         }
		//     }
		//     Ok(false) => {
		//         warn!(
		//             "Transaction {} not yet confirmed on chain {}",
		//             tx_id, selected_chain
		//         );

		//         return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
		//             status: "pending".to_string(),
		//             signer_address: user_registration.ethereum_address.clone(),
		//             is_registered: true,
		//             amount: req.msg.amount,
		//             user_to_network_tx_id: None,
		//             network_to_target_tx_id: None,
		//             vault_to_network_tx_id: None,
		//             error_message: Some("Transaction not yet confirmed on chain".to_string()),
		//         }));
		//     }
		//     Err(e) => {
		//         error!("Tx confirmation API returned error: {}", e);
		//         return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
		//             status: "error".to_string(),
		//             signer_address: user_registration.ethereum_address.clone(),
		//             is_registered: true,
		//             amount: req.msg.amount,
		//             user_to_network_tx_id: None,
		//             network_to_target_tx_id: None,
		//             vault_to_network_tx_id: None,
		//             error_message: Some(format!("Tx confirmation API error: {}", e)),
		//         }));
		//     }
		// }
		// If confirmed, continue processing
	}

	match handle_deposit_intent(
		req.msg.clone(),
		user_eth_address,
		message_tx,
		transaction_type,
		dkg_storage.clone(),
	)
	.await
	{
		Ok(_) => {
			info!(
				"✅ Deposit intent processed successfully for user: {}",
				user_registration.ethereum_address
			);
		},
		Err(e) => {
			error!("❌ Failed to process deposit intent: {:?}", e);

			// Just return the raw error message as it is
			let error_message = format!("{:?}", e);

			return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
				status: "error".to_string(),
				signer_address: user_registration.ethereum_address.clone(),
				is_registered: true,
				amount: req.msg.amount,
				user_to_network_tx_id: None,
				network_to_target_tx_id: None,
				vault_to_network_tx_id: None,
				final_solver_id: None,
				error_message: Some(error_message),
			}));
		},
	}

	// Wait for the actual transaction result (success with TX ID or chain error)
	let intent_hash_hex = hex::encode(&intent_hash);
	info!("✅ Deposit intent submitted successfully. Intent hash: {}", intent_hash_hex);
	info!("⏳ Waiting for transaction to be processed by the network...");

	// Poll the database frequently for up to 10 seconds so that we can
	// return a response as soon as the transaction is available.
	let (u2n_tx_id, n2t_tx_id, v2n_tx_id, final_solver_id, chain_error) =
		wait_for_transaction_result(&user_registry, &intent_hash, 40).await;

	// Log the transaction IDs if recorded
	if let Some(ref tx_id_str) = u2n_tx_id {
		info!("✅ User->Network transaction completed with ID: {:?}", tx_id_str);
	}
	if let Some(ref tx_id_str) = n2t_tx_id {
		info!("✅ Network->Target transaction completed with ID: {:?}", tx_id_str);
	}
	if let Some(ref tx_id_str) = v2n_tx_id {
		info!("✅ Vault->Network transaction completed with ID: {:?}", tx_id_str);
	}

	if u2n_tx_id.is_some() || n2t_tx_id.is_some() || v2n_tx_id.is_some() {
		// At least one transaction succeeded
		Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
			status: "success".to_string(),
			signer_address: user_registration.ethereum_address.clone(),
			is_registered: true,
			amount: req.msg.amount,
			user_to_network_tx_id: u2n_tx_id,
			network_to_target_tx_id: n2t_tx_id,
			vault_to_network_tx_id: v2n_tx_id,
			final_solver_id: final_solver_id.clone(),
			error_message: None,
		}))
	} else if let Some(error_msg) = chain_error {
		// Chain error occurred - return the actual error from blockchain
		Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
			status: "error".to_string(),
			signer_address: user_registration.ethereum_address.clone(),
			is_registered: true,
			amount: req.msg.amount,
			user_to_network_tx_id: None,
			network_to_target_tx_id: None,
			vault_to_network_tx_id: None,
			final_solver_id: final_solver_id.clone(),
			error_message: Some(error_msg), // This is the actual chain error!
		}))
	} else {
		// No transaction ID and no error after waiting - still processing or timeout
		Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
			status: "timeout".to_string(),
			signer_address: user_registration.ethereum_address.clone(),
			is_registered: true,
			amount: req.msg.amount,
			user_to_network_tx_id: None,
			network_to_target_tx_id: None,
			vault_to_network_tx_id: None,
			final_solver_id,
			error_message: Some(format!(
				"Transaction processing timeout. Intent hash: {}. The transaction may still be processing or may have failed. Please check the status later.",
				intent_hash_hex
			)),
		}))
	}
}

pub async fn handle_deposit_intent(
	intent: DepositIntent,
	user_eth_address: Option<String>,
	message_tx: std::sync::Arc<tokio::sync::Mutex<mpsc::Sender<ChannelMessage>>>,
	transaction_type: crate::types::TransactionType,
	dkg_storage: std::sync::Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
	info!("📝 HTTP: Received deposit intent request: {:?}", intent);
	info!("📝 HTTP: User eth address for signing: {:?}", user_eth_address);
	let mut required_amount_u128 = 0;

	// Only do price conversion for NetworkToTarget, else just use intent.amount
	if matches!(transaction_type, crate::types::TransactionType::NetworkToTarget) {
		// Fetch current prices for BTC and TICS to determine the
		// value equivalence between source and target chains.
		let prices = fetch_crypto_prices()
			.await
			.map_err(|_| warp::reject::custom(TransactionError::NetworkError))?;

		// Helper closure to map chain names to the price symbols returned by
		// the price API. Any non-Bitcoin chain is treated as TICS (our EVM token).
		let chain_to_symbol = |chain: &str| match chain.to_lowercase().as_str() {
			"btc" | "bitcoin" => "BTC",
			_ => "TICS",
		};

		let source_symbol = chain_to_symbol(&intent.source_chain);
		let target_symbol = chain_to_symbol(&intent.target_chain);

		let source_price = *prices
			.get(source_symbol)
			.ok_or_else(|| warp::reject::custom(TransactionError::NetworkError))?;
		let target_price = *prices
			.get(target_symbol)
			.ok_or_else(|| warp::reject::custom(TransactionError::NetworkError))?;

		info!(
			"💱 Conversion: {} {} (source chain: {}) @ {} per unit --> {} (target chain: {}) @ {} per unit",
			intent.amount, source_symbol, intent.source_chain, source_price, target_symbol, intent.target_chain, target_price
		);

		// Convert the intent amount using the price ratio so we can compare
		// against the balance of the address on the chain we are about to
		// spend from.
		let target_smallest = convert_src_smallest_to_dst_smallest(
			intent.amount,
			&intent.source_chain,
			&intent.target_chain,
			&prices,
		)?;

		required_amount_u128 = target_smallest;

		info!(
			"💱 Conversion: {} {} (source) is equivalent to {} {} (target) smallest units",
			intent.amount, source_symbol, required_amount_u128, target_symbol
		);
	} else {
		// For VaultToNetwork and other types, use the intent amount plus 10%
		let base_amount = intent.amount + (intent.amount / 10);
		required_amount_u128 = base_amount;
		info!("💱 No price conversion needed. Using intent amount as required amount: {} -> {} (source chain: {})", base_amount, required_amount_u128, intent.source_chain);
	}

	// Additional balance validation for NetworkToTarget and VaultToNetwork
	// if matches!(
	//     transaction_type,
	//     crate::types::TransactionType::NetworkToTarget
	//         | crate::types::TransactionType::VaultToNetwork
	// ) {
	//     // Determine which chain to check based on the transaction type
	//     let chain_to_use = match transaction_type {
	//         crate::types::TransactionType::NetworkToTarget => intent.target_chain.to_lowercase(),
	//         crate::types::TransactionType::VaultToNetwork => intent.source_chain.to_lowercase(),
	//         _ => unreachable!(),
	//     };

	// Decide which address to check: network address or vault address
	// let (address_to_check, blockchain) =
	//     if crate::utils::transaction::is_evm_chain(&chain_to_use) {
	//         let address = match transaction_type {
	//             crate::types::TransactionType::NetworkToTarget => {
	//                 let group_key = dkg_storage
	//                     .get_final_public()
	//                     .await
	//                     .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?
	//                     .ok_or_else(|| {
	//                         warp::reject::custom(TransactionError::InvalidRequest)
	//                     })?;
	//                 let mut addr = crate::utils::get_eth_address_from_group_key(group_key);
	//                 if !addr.starts_with("0x") {
	//                     addr = format!("0x{}", addr);
	//                 }
	//                 addr
	//             }
	//             crate::types::TransactionType::VaultToNetwork => {
	//                 let (vault_eth, _) = dkg_storage
	//                     .get_vault_addresses()
	//                     .await
	//                     .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?
	//                     .ok_or_else(|| {
	//                         warp::reject::custom(TransactionError::InvalidRequest)
	//                     })?;
	//                 vault_eth
	//             }
	//             _ => unreachable!(),
	//         };
	//         (address, "eth".to_string())
	//     } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
	//         let address = match transaction_type {
	//             crate::types::TransactionType::NetworkToTarget => {
	//                 let group_key = dkg_storage
	//                     .get_final_public()
	//                     .await
	//                     .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?
	//                     .ok_or_else(|| {
	//                         warp::reject::custom(TransactionError::InvalidRequest)
	//                     })?;
	//                 crate::utils::get_btc_address_from_group_key(group_key)
	//             }
	//             crate::types::TransactionType::VaultToNetwork => {
	//                 let (_, vault_btc) = dkg_storage
	//                     .get_vault_addresses()
	//                     .await
	//                     .map_err(|_| warp::reject::custom(TransactionError::InvalidRequest))?
	//                     .ok_or_else(|| {
	//                         warp::reject::custom(TransactionError::InvalidRequest)
	//                     })?;
	//                 vault_btc
	//             }
	//             _ => unreachable!(),
	//         };
	//         (address, "btc".to_string())
	//     } else {
	//         warn!("Unsupported chain for balance validation: {}", chain_to_use);
	//         return Err(warp::reject::custom(TransactionError::InvalidRequest));
	//     };

	// let balance = fetch_balance(&address_to_check, &blockchain)
	//     .await
	//     .map_err(|_| warp::reject::custom(TransactionError::NetworkError))?;

	// info!(
	//     "💰 Balance check: address {} on chain {} has balance {} (required: {})",
	//     address_to_check, chain_to_use, balance, required_amount_u128
	// );

	// if balance < required_amount_u128 {
	//     warn!(
	//         "Insufficient balance for address {} on chain {}: required {}, found {}",
	//         address_to_check, chain_to_use, required_amount_u128, balance
	//     );
	//     return Err(warp::reject::custom(TransactionError::InvalidRequest));
	// }
	// }

	let intent_id = format!("intent-{}", Uuid::new_v4());
	let deposit_intent_msg = ChannelMessage::DepositIntent {
		intent: intent.clone(),
		intent_id: intent_id.clone(),
		user_eth_address: user_eth_address.clone(),
		transaction_type: transaction_type.clone(),
		amount: required_amount_u128,
	};

	let tx_sender = message_tx.lock().await;
	if let Err(e) = tx_sender.send(deposit_intent_msg).await {
		warn!("Failed to send deposit intent to network: {:?}", e);
		return Err(warp::reject::custom(TransactionError::NetworkError));
	}

	info!("✅ HTTP: Deposit intent submitted to network: {}", intent_id);

	Ok(warp::reply::json(&DepositIntentResponse {
		intent_id,
		status: "submitted".to_string(),
		message: "Deposit intent submitted to P_2_P network".to_string(),
		raw_transaction: None,
	}))
}
