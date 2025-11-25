use std::{sync::Arc, time::Instant};

use hex;
use ethers::types::U256;
use serde_json;
use sha3::{Digest, Keccak256};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

use crate::{
    database::{DkgStorage, RewardStorage},
    types::{
        intent::{DepositIntent, DepositIntentResponse, TransactionResponse, TransactionType},
        messaging::ChannelMessage,
        rpc::RPCRequest,
        rpc_server::{
            ClaimRewardRequest, ClaimRewardResponse, DKGStatusResponse,
            EnhancedUserRegistrationResponse, GetRewardSolverRequest, GetRewardSolverResponse,
            HeartbeatResponse, NodeIdResponse, NodeStatus, RequestContext, UptimeResponse,
            UserInfoResponse, UserMpcDepositRequest, UserMpcDepositVerifyResponse,
            UserRegistrationRequest, WithdrawLiquidityRequest, WithdrawLiquidityResponse,
        },
    },
    user_intent_manager::{checksum_from_any, UserIntentManager},
};

use super::{
    errors::{RpcError, TransactionError},
    utils::{
        convert_src_smallest_to_dst_smallest, fetch_crypto_prices, get_actual_dkg_secret_share,
        normalize_eth_signature, recover_eth_address_secp, wait_for_reward_transaction_ids,
        wait_for_withdraw_liquidity_transaction_ids,
        wait_for_transaction_result,
    },
};

pub(crate) async fn handle_deposit_intent(
    intent: DepositIntent,
    user_eth_address: Option<String>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    transaction_type: TransactionType,
    _dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📝 HTTP: Received deposit intent request");
    if let Some(addr) = &user_eth_address {
        info!("📝 HTTP: User eth address provided for signing: {}", addr);
    }
    let required_amount_u128 = if matches!(transaction_type, TransactionType::NetworkToTarget) {
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

        info!("💱 Conversion: computed source->target equivalence using current prices");
        info!(
            "💱 Prices - source: {}={}, target: {}={}",
            source_symbol, source_price, target_symbol, target_price
        );

        let target_smallest = convert_src_smallest_to_dst_smallest(
            intent.amount,
            &intent.source_chain,
            &intent.target_chain,
            &prices,
        )?;

        info!("💱 Conversion: source amount converted to target smallest units");
        target_smallest
    } else {
        // For VaultToNetwork and other types, use the intent amount plus 10%
        let base_amount = intent.amount + (intent.amount / 10);
        info!("💱 No price conversion needed; using adjusted intent amount");
        base_amount
    };

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

    info!(
        "✅ HTTP: Deposit intent submitted to network: {}, required_amount={}",
        intent_id, required_amount_u128
    );

    Ok(warp::reply::json(&DepositIntentResponse {
        intent_id,
        status: "submitted".to_string(),
        message: "Deposit intent submitted to P_2_P network".to_string(),
        raw_transaction: None,
    }))
}

fn parse_withdraw_amount(value: &str, asset_label: &str) -> Result<U256, String> {
    U256::from_dec_str(value)
        .map_err(|_| format!("Invalid {} withdraw amount: {}", asset_label, value))
}

fn ensure_withdraw_amount_bounds(value: &U256, asset_label: &str) -> Result<(), String> {
    if value.is_zero() {
        return Err(format!(
            "{} withdraw amount must be greater than zero",
            asset_label
        ));
    }
    if value.bits() > 128 {
        return Err(format!(
            "{} withdraw amount exceeds supported limit",
            asset_label
        ));
    }
    Ok(())
}

fn select_withdraw_amount(
    requested: Option<&String>,
    available: Option<&String>,
    asset_label: &str,
) -> Result<Option<String>, String> {
    match (requested, available) {
        (Some(req), Some(avail)) => {
            let req_val = parse_withdraw_amount(req, asset_label)?;
            ensure_withdraw_amount_bounds(&req_val, asset_label)?;
            let avail_val = parse_withdraw_amount(avail, asset_label)?;
            if req_val > avail_val {
                return Err(format!(
                    "{} withdraw amount exceeds available liquidity",
                    asset_label
                ));
            }
            Ok(Some(req.clone()))
        }
        (Some(_), None) => Err(format!(
            "No {} liquidity available to fulfill withdrawal",
            asset_label
        )),
        (None, Some(avail)) => {
            let avail_val = parse_withdraw_amount(avail, asset_label)?;
            if avail_val.is_zero() {
                return Ok(None);
            }
            ensure_withdraw_amount_bounds(&avail_val, asset_label)?;
            Ok(Some(avail.clone()))
        }
        (None, None) => Ok(None),
    }
}

pub(crate) async fn handle_register_user(
    request: UserRegistrationRequest,
    user_intent_manager: Arc<UserIntentManager>,
    dkg_storage: Arc<DkgStorage>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    node_id: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "👤 HTTP: Received user registration request for address: {}",
        request.ethereum_address
    );

    // Input validation
    let addr_cs = match super::errors::validate_ethereum_address(&request.ethereum_address) {
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
        }
    };

    // Check if user is already registered
    if let Some(_existing_user) = user_intent_manager.get_user_by_address(&addr_cs).await {
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
    match user_intent_manager
        .register_user(&addr_cs, dkg_secret_share.as_ref(), &node_id)
        .await
    {
        Ok(registration) => {
            info!(
                "✅ HTTP: User registration successful for address: {}",
                addr_cs
            );

            if registration.tweaked_secret_share.is_some() {
                info!(
                    "🔑 HTTP: Computed and stored tweaked secret share for user: {}",
                    addr_cs
                );
            } else {
                warn!(
                    "⚠️ HTTP: No tweaked secret share computed for user: {}",
                    addr_cs
                );
            }

            let user_reg_msg = ChannelMessage::UserRegistration {
                ethereum_address: addr_cs.clone(),
                node_id: node_id.to_string(),
            };

            if let Ok(tx) = message_tx.try_lock() {
                if let Err(e) = tx.send(user_reg_msg).await {
                    error!(
                        "❌ Failed to send user registration message to network: {}",
                        e
                    );
                    warn!("⚠️ User registered locally but network broadcast failed");
                } else {
                    info!("📡 User registration message sent to network layer for broadcasting");
                }
            } else {
                warn!("⚠️ Could not acquire message channel lock for network broadcast");
            }

            info!("⏳ Waiting for derived addresses to be populated...");
            let mut attempts = 0;
            const MAX_ATTEMPTS: u8 = 10; // Wait up to 10 seconds

            let mut final_registration = registration.clone();
            while attempts < MAX_ATTEMPTS {
                match user_intent_manager.get_user_by_address(&addr_cs).await {
                    Some(updated_user) => {
                        if updated_user.derived_eth_address.is_some()
                            && updated_user.derived_btc_address.is_some()
                        {
                            final_registration = updated_user;
                            info!("✅ Derived addresses are now available!");
                            break;
                        }
                    }
                    None => {
                        error!("❌ User disappeared from registry during address derivation");
                        break;
                    }
                }

                attempts += 1;
                if attempts < MAX_ATTEMPTS {
                    info!(
                        "⏳ Attempt {}/{}: Derived addresses not ready yet, waiting 1 second...",
                        attempts, MAX_ATTEMPTS
                    );
                    sleep(Duration::from_secs(1)).await;
                }
            }

            if attempts >= MAX_ATTEMPTS {
                warn!(
                    "⚠️ Derived addresses not available after {} attempts",
                    MAX_ATTEMPTS
                );
            }

            if let Some(eth_addr) = &final_registration.derived_eth_address {
                info!(
                    "📬 HTTP: Derived ETH address stored for {} -> {}",
                    addr_cs, eth_addr
                );
            }
            if let Some(btc_addr) = &final_registration.derived_btc_address {
                info!(
                    "📬 HTTP: Derived BTC address stored for {} -> {}",
                    addr_cs, btc_addr
                );
            }

            let response = EnhancedUserRegistrationResponse {
                status: "success".to_string(),
                message: "User registered successfully".to_string(),
                derived_eth_address: final_registration.derived_eth_address,
                derived_btc_address: final_registration.derived_btc_address,
                error: None,
            };

            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            error!(
                "❌ HTTP: User registration failed for address {}: {}",
                addr_cs, e
            );

            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "User registration failed".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(RpcError::RegistrationFailed(e.to_string()).to_error_response()),
            };

            Ok(warp::reply::json(&error_response))
        }
    }
}

pub(crate) async fn handle_user_mpc_deposit(
    req: UserMpcDepositRequest,
    user_intent_manager: Arc<UserIntentManager>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    dkg_storage: Arc<DkgStorage>,
    request_context: RequestContext,
) -> Result<impl warp::Reply, warp::Rejection> {
    let intent_json = match serde_json::to_string(&req.msg) {
        Ok(json) => json,
        Err(e) => {
            error!(
                request_id = %request_context.request_id,
                error = %e,
                "❌ Failed to serialize deposit intent for hashing"
            );
            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                status: "error".to_string(),
                signer_address: "".to_string(),
                is_registered: false,
                amount: req.msg.amount,
                user_to_network_tx_id: None,
                network_to_target_tx_id: None,
                vault_to_network_tx_id: None,
                final_solver_id: None,
                error_message: Some("Invalid deposit intent payload".to_string()),
            }));
        }
    };
    let intent_bytes = intent_json.as_bytes();
    let intent_hash = Keccak256::digest(intent_bytes);
    let intent_hash_hex = hex::encode(intent_hash);
    let span = info_span!(
        "user_mpc_deposit",
        request_id = %request_context.request_id,
        intent_hash = %intent_hash_hex
    );
    let _enter = span.enter();

    info!("🧾 HTTP: user_mpc_deposit received");

    if let Some(ref idempotency_key) = request_context.idempotency_key {
        match user_intent_manager
            .register_idempotency_key(idempotency_key, &intent_hash_hex)
            .await
        {
            Ok(already_seen) => {
                if already_seen {
                    info!(
                        request_id = %request_context.request_id,
                        "♻️ Idempotent replay detected for deposit intent"
                    );
                } else {
                    info!(
                        request_id = %request_context.request_id,
                        "🆔 Recorded new idempotency key for deposit intent"
                    );
                }
            }
            Err(e) => {
                error!(
                    request_id = %request_context.request_id,
                    error = %e,
                    "❌ Idempotency key reuse with different intent"
                );
                return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                    status: "error".to_string(),
                    signer_address: "".to_string(),
                    is_registered: false,
                    amount: req.msg.amount,
                    user_to_network_tx_id: None,
                    network_to_target_tx_id: None,
                    vault_to_network_tx_id: None,
                    final_solver_id: None,
                    error_message: Some(
                        "Idempotency key already used for another intent".to_string(),
                    ),
                }));
            }
        }
    } else {
        warn!(
            request_id = %request_context.request_id,
            "⚠️ No Idempotency-Key header provided for deposit request"
        );
    }

    let mut transaction_ids = Vec::new();
    let tx_mapping = user_intent_manager
        .get_intent_transaction_ids(&intent_hash_hex)
        .await;
    if let Some(tx_ids) = user_intent_manager
        .get_intent_transaction_ids(&intent_hash_hex)
        .await
    {
        if tx_ids.error_message.is_none() {
            if let Some(ref user_to_network_tx) = tx_ids.user_to_network_tx_id {
                transaction_ids.push(user_to_network_tx.clone());
            }
            if let Some(ref network_to_target_tx) = tx_ids.network_to_target_tx_id {
                transaction_ids.push(network_to_target_tx.clone());
            }
        }
    }

    let transaction_type = if transaction_ids.len() == 1 {
        TransactionType::NetworkToTarget
    } else if transaction_ids.is_empty() {
        TransactionType::UserToVault
    } else {
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

    info!(
        "🔐 Processing MPC deposit - Intent hash: {:?}, Amount: {}",
        intent_hash, req.msg.amount
    );
    info!("📝 Server JSON serialization prepared");
    info!(
        "📏 JSON length: {}, First 100 chars: {}",
        intent_json.len(),
        if intent_json.len() > 100 {
            &intent_json[0..100]
        } else {
            &intent_json
        }
    );

    let user_registration = match user_intent_manager
        .get_user_by_intent_hash(&intent_hash_hex)
        .await
    {
        Some(existing_user) => existing_user,
        None => {
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
                        }
                    };
                    let (signer, _used_personal) = match recover_eth_address_secp(
                        intent_bytes,
                        &compact,
                        v,
                        true,
                    ) {
                        Ok(addr) => (addr, true),
                        Err(e1) => {
                            warn!("⚠️ personal_sign recovery failed: {}", e1);
                            match recover_eth_address_secp(intent_bytes, &compact, v, false) {
                                Ok(addr) => (addr, false),
                                Err(e2) => {
                                    error!(
                                            "❌ Both signature recovery methods failed: personal_sign={}, raw={}",
                                            e1, e2
                                        );
                                    return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
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
                                    }));
                                }
                            }
                        }
                    };
                    let user_reg = match user_intent_manager.get_user_by_address(&signer).await {
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
                        }
                    };
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
                }
                None => {
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
                }
            }
        }
    };

    let user_eth_address = match transaction_type {
        crate::types::TransactionType::UserToVault => {
            Some(user_registration.ethereum_address.clone())
        }
        _ => None,
    };

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

    if let Some(ref tx_id) = req.tx_id {
        let source_chain = req.msg.source_chain.to_lowercase();
        let target_chain = req.msg.target_chain.to_lowercase();
        let selected_chain = match chain_to_check {
            Some("target") => &target_chain,
            Some("source") => &source_chain,
            Some("tics") | Some(_) => "tics",
            None => "tics",
        };
        info!(
            "🔎 Would check tx {} confirmation on chain {} (functionality disabled)",
            tx_id, selected_chain
        );
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
        }
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
        }
    }

    let intent_hash_hex = hex::encode(&intent_hash);
    info!(
        "✅ Deposit intent submitted successfully. Intent hash: {}",
        intent_hash_hex
    );
    info!("⏳ Waiting for transaction to be processed by the network...");

    let (u2n_tx_id, n2t_tx_id, v2n_tx_id, final_solver_id, chain_error) =
        wait_for_transaction_result(&user_intent_manager, &intent_hash, 40).await;

    if let Some(ref tx_id_str) = u2n_tx_id {
        info!(
            "✅ User->Network transaction completed with ID: {:?}",
            tx_id_str
        );
    }
    if let Some(ref tx_id_str) = n2t_tx_id {
        info!(
            "✅ Network->Target transaction completed with ID: {:?}",
            tx_id_str
        );
    }
    if let Some(ref tx_id_str) = v2n_tx_id {
        info!(
            "✅ Vault->Network transaction completed with ID: {:?}",
            tx_id_str
        );
    }

    let duration_ms = request_context.started_at.elapsed().as_millis() as u64;

    if u2n_tx_id.is_some() || n2t_tx_id.is_some() || v2n_tx_id.is_some() {
        info!(
            request_id = %request_context.request_id,
            duration_ms,
            "✅ Deposit request finished with on-chain receipts"
        );
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
        warn!(
            request_id = %request_context.request_id,
            duration_ms,
            "⚠️ Deposit processing returned chain error"
        );
        Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            signer_address: user_registration.ethereum_address.clone(),
            is_registered: true,
            amount: req.msg.amount,
            user_to_network_tx_id: None,
            network_to_target_tx_id: None,
            vault_to_network_tx_id: None,
            final_solver_id: final_solver_id.clone(),
            error_message: Some(error_msg),
        }))
    } else {
        warn!(
            request_id = %request_context.request_id,
            duration_ms,
            "⚠️ Deposit processing timed out"
        );
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

pub(crate) async fn handle_get_user_info(
    ethereum_address: String,
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🔍 HTTP: Received user info request for address: {}",
        ethereum_address
    );

    let addr_cs = match super::errors::validate_ethereum_address(&ethereum_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!(
                "❌ HTTP: Address validation failed for '{}': {:?}",
                ethereum_address, e
            );
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
        }
    };

    info!(
        "🔍 HTTP: Looking up user info for (normalized): {}",
        addr_cs
    );

    match user_intent_manager.get_user_by_address(&addr_cs).await {
        Some(registration) => {
            info!("✅ HTTP: Found user info for {}", addr_cs);

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
        }
        None => {
            info!("❌ HTTP: User not found for {}", addr_cs);

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
        }
    }
}

pub(crate) async fn handle_get_node_id(
    node_id: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&NodeIdResponse { node_id }))
}

pub(crate) async fn handle_get_status(
    _message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("here at handle status!! ");
    Ok(warp::reply::json(&NodeStatus {
        peer_id: "dummy-peer-id".to_string(),
        connected_peers: 0,
        dkg_status: "unknown".to_string(),
        is_ready: true,
    }))
}

pub(crate) async fn handle_heartbeat() -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&HeartbeatResponse {
        status: "alive".to_string(),
    }))
}

pub(crate) async fn handle_get_uptime(
    start_time: Arc<Instant>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let uptime = start_time.elapsed().as_secs();
    Ok(warp::reply::json(&UptimeResponse {
        uptime_seconds: uptime,
    }))
}

pub(crate) async fn handle_get_dkg_status(
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🔍 HTTP: Checking DKG status");

    let secret_share_available = match dkg_storage.get_final_secret().await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            warn!("Failed to read DKG secret share: {}", e);
            false
        }
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

pub(crate) async fn handle_start_dkg(
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("🚀 HTTP: RPC request to start DKG");

    let dkg_request = RPCRequest::StartADKG;
    let gossipsub_msg = crate::types::GossipsubMessage::DKGCommand(dkg_request);
    let dkg_data = serde_json::to_vec(&gossipsub_msg).map_err(|e| {
        warn!("Failed to serialize DKG request: {}", e);
        warp::reject::custom(TransactionError::SerializationError)
    })?;

    let tx_sender = message_tx.lock().await;
    if let Err(e) = tx_sender
        .send(ChannelMessage::Broadcast {
            topic: "dkg-commands".to_string(),
            data: dkg_data,
        })
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

pub(crate) async fn handle_get_reward_solver(
    req: GetRewardSolverRequest,
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🔍 HTTP: get_reward_solver request for solver: {}",
        req.solver_address
    );

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
        }
    };

    let reward_btc = user_intent_manager
        .get_solver_reward_btc(&normalized_address)
        .await;
    let reward_tics = user_intent_manager
        .get_solver_reward_tics(&normalized_address)
        .await;

    let reward_btc_str = reward_btc.as_ref().map(|v| v.to_string());
    let reward_tics_str = reward_tics.as_ref().map(|v| v.to_string());

    let _legacy_reward = match (reward_btc, reward_tics) {
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

pub(crate) async fn handle_claim_reward(
    req: ClaimRewardRequest,
    user_intent_manager: Arc<UserIntentManager>,
    _reward_storage: Arc<RewardStorage>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🎁 HTTP: claim_reward request for ETH: {:?}, BTC: {:?}",
        req.ethereum_address, req.btc_address
    );
    if req.ethereum_address.is_none() && req.btc_address.is_none() {
        warn!("❌ Both addresses are None - at least one address must be provided");
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: None,
            btc_address: None,
            reward_btc: None,
            reward_tics: None,
            message: "At least one address must be provided".to_string(),
            error_message: Some("Both ethereum_address and btc_address cannot be None".to_string()),
            tics_reward_tx_id: None,
            btc_reward_tx_id: None,
        }));
    }

    let normalized_eth_address = if let Some(eth_addr) = &req.ethereum_address {
        match super::errors::validate_ethereum_address(eth_addr) {
            Ok(addr) => Some(addr),
            Err(e) => {
                warn!("❌ Invalid Ethereum address format: {:?}", e);
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    ethereum_address: req.ethereum_address,
                    btc_address: req.btc_address,
                    reward_btc: None,
                    reward_tics: None,
                    message: "Invalid Ethereum address format".to_string(),
                    error_message: Some(format!("Invalid Ethereum address: {:?}", e)),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        }
    } else {
        None
    };

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
                message: "Invalid signature format".to_string(),
                error_message: Some(format!("Invalid signature: {:?}", e)),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
    };

    let msg_bytes = req.message.as_bytes();

    let solver_address = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
        Ok(addr) => addr,
        Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
            Ok(addr) => addr,
            Err(e2) => {
                error!(
                    "❌ Failed to recover address: personal_sign={}, raw={}",
                    e1, e2
                );
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    ethereum_address: normalized_eth_address,
                    btc_address: req.btc_address,
                    reward_btc: None,
                    reward_tics: None,
                    message: "Failed to recover signature".to_string(),
                    error_message: Some(format!(
                        "Failed to recover signature: personal_sign={}, raw={}",
                        e1, e2
                    )),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        },
    };

    info!(
        "🔐 Recovered solver address from signature: {}",
        solver_address
    );

    let reward_btc = user_intent_manager
        .get_solver_reward_btc(solver_address.as_str())
        .await
        .filter(|v| !v.is_zero());
    let reward_tics = user_intent_manager
        .get_solver_reward_tics(solver_address.as_str())
        .await
        .filter(|v| !v.is_zero());

    let reward_btc_str = reward_btc.as_ref().map(|v| v.to_string());
    let reward_tics_str = reward_tics.as_ref().map(|v| v.to_string());

    let previous_tics_tx_id = user_intent_manager
        .get_solver_tics_txn_hash(solver_address.as_str())
        .await;
    let previous_btc_tx_id = user_intent_manager
        .get_solver_btc_txn_hash(solver_address.as_str())
        .await;

    let expect_tics_tx = reward_tics_str.is_some() && req.ethereum_address.as_ref().is_some();
    let expect_btc_tx = reward_btc_str.is_some() && req.btc_address.as_ref().is_some();

    if reward_btc_str.is_none() && reward_tics_str.is_none() {
        warn!(
            "❌ No rewards available (non-zero) for solver address: {}",
            solver_address
        );
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: normalized_eth_address,
            btc_address: req.btc_address,
            reward_btc: None,
            reward_tics: None,
            message: "No rewards available to claim".to_string(),
            error_message: Some("No rewards available to claim".to_string()),
            tics_reward_tx_id: None,
            btc_reward_tx_id: None,
        }));
    }

    let claim_msg = ChannelMessage::ClaimReward {
        solver_address: solver_address.clone(),
        btc_address: req.btc_address.clone(),
        eth_address: req.ethereum_address.clone(),
        reward_btc: reward_btc_str.clone(),
        reward_tics: reward_tics_str.clone(),
        transaction_type: "reward_txn".to_string(),
    };

    let tx_sender = message_tx.lock().await;
    if let Err(e) = tx_sender.send(claim_msg).await {
        warn!("Failed to send claim reward message: {}", e);
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: normalized_eth_address,
            btc_address: req.btc_address,
            reward_btc: reward_btc_str,
            reward_tics: reward_tics_str,
            message: "Failed to process reward claim".to_string(),
            error_message: Some(format!("Network error: {}", e)),
            tics_reward_tx_id: None,
            btc_reward_tx_id: None,
        }));
    }

    drop(tx_sender);

    let wait_timeout_secs = 40;
    let (tics_reward_tx_id, btc_reward_tx_id) = if expect_tics_tx || expect_btc_tx {
        wait_for_reward_transaction_ids(
            &user_intent_manager,
            solver_address.as_str(),
            expect_tics_tx,
            expect_btc_tx,
            previous_tics_tx_id,
            previous_btc_tx_id,
            wait_timeout_secs,
        )
        .await
    } else {
        (None, None)
    };

    if let Some(ref tx_id) = tics_reward_tx_id {
        info!(
            "✅ Recorded TICS reward transaction ID {} for solver {}",
            tx_id, solver_address
        );
    } else if expect_tics_tx {
        warn!(
            "⚠️ Timed out waiting for TICS reward transaction ID for solver {} after {} seconds",
            solver_address, wait_timeout_secs
        );
    }

    if let Some(ref tx_id) = btc_reward_tx_id {
        info!(
            "✅ Recorded BTC reward transaction ID {} for solver {}",
            tx_id, solver_address
        );
    } else if expect_btc_tx {
        warn!(
            "⚠️ Timed out waiting for BTC reward transaction ID for solver {} after {} seconds",
            solver_address, wait_timeout_secs
        );
    }

    info!(
        "✅ Reward claim processed successfully for solver: {}, BTC: {:?}",
        solver_address, req.btc_address
    );

    Ok(warp::reply::json(&ClaimRewardResponse {
        status: "success".to_string(),
        ethereum_address: normalized_eth_address,
        btc_address: req.btc_address,
        reward_btc: reward_btc_str,
        reward_tics: reward_tics_str,
        message: "Reward claim processed successfully".to_string(),
        error_message: None,
        tics_reward_tx_id,
        btc_reward_tx_id,
    }))
}

pub(crate) async fn handle_withdraw_liquidity(
    req: WithdrawLiquidityRequest,
    user_intent_manager: Arc<UserIntentManager>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "💧 HTTP: withdraw_liquidity request with message: {}",
        req.message
    );

    // Normalize and validate signature
    let (compact, v) = match normalize_eth_signature(&req.signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ Invalid signature format: {}", e);
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: "".to_string(),
                liquidity_btc: None,
                liquidity_tics: None,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Invalid signature format".to_string(),
                error_message: Some(format!("Invalid signature: {:?}", e)),
            }));
        }
    };

    // Recover address from signature
    let msg_bytes = req.message.as_bytes();
    let solver_address = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
        Ok(addr) => addr,
        Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
            Ok(addr) => addr,
            Err(e2) => {
                error!(
                    "❌ Failed to recover address: personal_sign={}, raw={}",
                    e1, e2
                );
                return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: "".to_string(),
                liquidity_btc: None,
                liquidity_tics: None,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Failed to recover signature".to_string(),
                error_message: Some(format!(
                    "Failed to recover signature: personal_sign={}, raw={}",
                    e1, e2
                )),
            }));
            }
        },
    };

    info!(
        "🔐 Recovered solver address from signature: {}",
        solver_address
    );

    // Normalize the solver address
    let normalized_address = match checksum_from_any(&solver_address) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("❌ Invalid solver address format: {}", e);
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: solver_address,
                liquidity_btc: None,
                liquidity_tics: None,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Invalid solver address format".to_string(),
                error_message: Some(format!("Invalid address format: {}", e)),
            }));
        }
    };

    // Check if address is a valid solver by checking liquidity in database
    let database = user_intent_manager.get_database();
    let solver_liquidity_key = format!("solver_liquidity:{}", normalized_address.to_lowercase());
    
    let liquidity_amounts: Option<Vec<String>> = match database.get_string::<Vec<String>>(&solver_liquidity_key) {
        Ok(amounts) => amounts,
        Err(e) => {
            warn!("❌ Failed to get solver liquidity from database: {}", e);
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: None,
                liquidity_tics: None,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Failed to check solver liquidity".to_string(),
                error_message: Some(format!("Database error: {}", e)),
            }));
        }
    };

    // Check if solver exists (has liquidity entry)
    if liquidity_amounts.is_none() {
        warn!(
            "❌ Address {} is not a valid solver (no liquidity entry found)",
            normalized_address
        );
        return Ok(warp::reply::json(&WithdrawLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address,
            liquidity_btc: None,
            liquidity_tics: None,
            ethereum_address: req.ethereum_address.clone(),
            btc_address: req.btc_address.clone(),
            tics_withdraw_tx_id: None,
            btc_withdraw_tx_id: None,
            message: "Address is not a valid solver".to_string(),
            error_message: Some("No liquidity entry found for this address".to_string()),
        }));
    }

    // Extract liquidity amounts (BTC at index 0, TICS at index 1)
    let amounts = liquidity_amounts.unwrap();
    let liquidity_btc_str = amounts.get(0).and_then(|s| {
        // Check if the string represents a non-zero value
        if s.trim().is_empty() || s == "0" {
            None
        } else {
            // Try to parse as U256 to validate, but keep original string
            match s.parse::<u128>() {
                Ok(val) if val > 0 => Some(s.clone()),
                Err(_) => {
                    // If it's too large for u128, check if it's not "0"
                    if s != "0" {
                        Some(s.clone())
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
    });
    let liquidity_tics_str = amounts.get(1).and_then(|s| {
        // Check if the string represents a non-zero value
        if s.trim().is_empty() || s == "0" {
            None
        } else {
            // Try to parse as U256 to validate, but keep original string
            match s.parse::<u128>() {
                Ok(val) if val > 0 => Some(s.clone()),
                Err(_) => {
                    // If it's too large for u128, check if it's not "0"
                    if s != "0" {
                        Some(s.clone())
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
    });

    // Check if any liquidity is available
    if liquidity_btc_str.is_none() && liquidity_tics_str.is_none() {
        warn!(
            "❌ No liquidity available for solver address: {}",
            normalized_address
        );
        return Ok(warp::reply::json(&WithdrawLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address,
            liquidity_btc: None,
            liquidity_tics: None,
            ethereum_address: req.ethereum_address.clone(),
            btc_address: req.btc_address.clone(),
            tics_withdraw_tx_id: None,
            btc_withdraw_tx_id: None,
            message: "No liquidity available to withdraw".to_string(),
            error_message: Some("No liquidity available to withdraw".to_string()),
        }));
    }

    info!(
        "✅ Valid solver with liquidity - BTC: {:?}, TICS: {:?}",
        liquidity_btc_str, liquidity_tics_str
    );

    let withdraw_tics_amount = match select_withdraw_amount(
        req.amount_tics.as_ref(),
        liquidity_tics_str.as_ref(),
        "TICS",
    ) {
        Ok(value) => value,
        Err(msg) => {
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                liquidity_btc: liquidity_btc_str.clone(),
                liquidity_tics: liquidity_tics_str.clone(),
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: msg.clone(),
                error_message: Some(msg),
            }));
        }
    };

    let withdraw_btc_amount = match select_withdraw_amount(
        req.amount_btc.as_ref(),
        liquidity_btc_str.as_ref(),
        "BTC",
    ) {
        Ok(value) => value,
        Err(msg) => {
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                liquidity_btc: liquidity_btc_str.clone(),
                liquidity_tics: liquidity_tics_str.clone(),
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: msg.clone(),
                error_message: Some(msg),
            }));
        }
    };

    if withdraw_tics_amount.is_some() && req.ethereum_address.is_none() {
        let msg = "Ethereum address is required to withdraw TICS liquidity".to_string();
        return Ok(warp::reply::json(&WithdrawLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address.clone(),
            liquidity_btc: liquidity_btc_str.clone(),
            liquidity_tics: liquidity_tics_str.clone(),
            ethereum_address: req.ethereum_address.clone(),
            btc_address: req.btc_address.clone(),
            tics_withdraw_tx_id: None,
            btc_withdraw_tx_id: None,
            message: msg.clone(),
            error_message: Some(msg),
        }));
    }

    if withdraw_btc_amount.is_some() && req.btc_address.is_none() {
        let msg = "BTC address is required to withdraw BTC liquidity".to_string();
        return Ok(warp::reply::json(&WithdrawLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address.clone(),
            liquidity_btc: liquidity_btc_str.clone(),
            liquidity_tics: liquidity_tics_str.clone(),
            ethereum_address: req.ethereum_address.clone(),
            btc_address: req.btc_address.clone(),
            tics_withdraw_tx_id: None,
            btc_withdraw_tx_id: None,
            message: msg.clone(),
            error_message: Some(msg),
        }));
    }

    // Initiate withdrawals for each provided address
    let mut initiated_tics = false;
    let mut initiated_btc = false;

    if let Some(amount_str) = withdraw_tics_amount.as_ref() {
        if let Some(address) = req.ethereum_address.as_ref() {
        info!(
            "🚰 [WITHDRAW] Initiating TICS withdrawal for solver {} -> {} (amount: {})",
            normalized_address, address, amount_str
        );
        let msg = ChannelMessage::WithdrawLiquidity {
            solver_address: normalized_address.clone(),
            btc_address: None,
            eth_address: Some(address.clone()),
            amount_btc: None,
            amount_tics: Some(amount_str.clone()),
            transaction_type: "withdraw_liquidity".to_string(),
        };
        let tx_sender = message_tx.lock().await;
        if let Err(e) = tx_sender.send(msg).await {
            error!(
                "❌ Failed to dispatch TICS withdraw message for solver {}: {}",
                normalized_address, e
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: liquidity_btc_str,
                liquidity_tics: liquidity_tics_str,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Failed to initiate TICS withdrawal".to_string(),
                error_message: Some(format!("Network error: {}", e)),
            }));
        }
        initiated_tics = true;
        } else {
            warn!(
                "⚠️ [WITHDRAW] TICS withdraw amount {} requested but no ethereum_address provided",
                amount_str
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: liquidity_btc_str,
                liquidity_tics: liquidity_tics_str,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Ethereum address is required for TICS withdrawal".to_string(),
                error_message: Some("Missing ethereum_address".to_string()),
            }));
        }
    }

    if let Some(amount_str) = withdraw_btc_amount.as_ref() {
        if let Some(address) = req.btc_address.as_ref() {
        info!(
            "🚰 [WITHDRAW] Initiating BTC withdrawal for solver {} -> {} (amount: {})",
            normalized_address, address, amount_str
        );
        let msg = ChannelMessage::WithdrawLiquidity {
            solver_address: normalized_address.clone(),
            btc_address: Some(address.clone()),
            eth_address: None,
            amount_btc: Some(amount_str.clone()),
            amount_tics: None,
            transaction_type: "withdraw_liquidity".to_string(),
        };
        let tx_sender = message_tx.lock().await;
        if let Err(e) = tx_sender.send(msg).await {
            error!(
                "❌ Failed to dispatch BTC withdraw message for solver {}: {}",
                normalized_address, e
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: liquidity_btc_str,
                liquidity_tics: liquidity_tics_str,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Failed to initiate BTC withdrawal".to_string(),
                error_message: Some(format!("Network error: {}", e)),
            }));
        }
        initiated_btc = true;
        } else {
            warn!(
                "⚠️ [WITHDRAW] BTC withdraw amount {} requested but no btc_address provided",
                amount_str
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: liquidity_btc_str,
                liquidity_tics: liquidity_tics_str,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "BTC address is required for BTC withdrawal".to_string(),
                error_message: Some("Missing btc_address".to_string()),
            }));
        }
    }

    // Get previous transaction IDs to detect new ones
    let previous_tics_tx_id = user_intent_manager
        .get_solver_tics_txn_hash(normalized_address.as_str())
        .await;
    let previous_btc_tx_id = user_intent_manager
        .get_solver_btc_txn_hash(normalized_address.as_str())
        .await;

    let wait_timeout_secs = 40;
    let (tics_withdraw_tx_id, btc_withdraw_tx_id) = if initiated_tics || initiated_btc {
        wait_for_withdraw_liquidity_transaction_ids(
            &user_intent_manager,
            normalized_address.as_str(),
            initiated_tics,
            initiated_btc,
            previous_tics_tx_id,
            previous_btc_tx_id,
            wait_timeout_secs,
        )
        .await
    } else {
        (None, None)
    };

    if let Some(ref tx_id) = tics_withdraw_tx_id {
        info!(
            "✅ Recorded TICS withdraw liquidity transaction ID {} for solver {}",
            tx_id, normalized_address
        );
    } else if initiated_tics {
        warn!(
            "⚠️ Timed out waiting for TICS withdraw liquidity transaction ID for solver {} after {} seconds",
            normalized_address, wait_timeout_secs
        );
    }

    if let Some(ref tx_id) = btc_withdraw_tx_id {
        info!(
            "✅ Recorded BTC withdraw liquidity transaction ID {} for solver {}",
            tx_id, normalized_address
        );
    } else if initiated_btc {
        warn!(
            "⚠️ Timed out waiting for BTC withdraw liquidity transaction ID for solver {} after {} seconds",
            normalized_address, wait_timeout_secs
        );
    }

    let message = if initiated_tics || initiated_btc {
        match (initiated_tics, initiated_btc) {
            (true, true) => "Liquidity withdrawals initiated for both TICS and BTC".to_string(),
            (true, false) => "Liquidity withdrawal initiated for TICS".to_string(),
            (false, true) => "Liquidity withdrawal initiated for BTC".to_string(),
            _ => unreachable!(),
        }
    } else {
        "No withdrawals were initiated (missing address or zero liquidity)".to_string()
    };

    info!(
        "✅ Withdraw liquidity processed successfully for solver: {}",
        normalized_address
    );

    Ok(warp::reply::json(&WithdrawLiquidityResponse {
        status: "success".to_string(),
        solver_address: normalized_address,
        liquidity_btc: liquidity_btc_str,
        liquidity_tics: liquidity_tics_str,
        ethereum_address: req.ethereum_address.clone(),
        btc_address: req.btc_address.clone(),
        tics_withdraw_tx_id,
        btc_withdraw_tx_id,
        message,
        error_message: None,
    }))
}
