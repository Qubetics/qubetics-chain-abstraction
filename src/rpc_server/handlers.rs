use std::{sync::Arc, time::Instant};

use ethers::types::{Address, U256};
use hex;
use serde_json;
use sha3::{Digest, Keccak256};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

use crate::{
    contract::{ContractClient, ContractConfig, SolverManagerContract},
    database::{DkgStorage, RewardStorage},
    types::{
        intent::{DepositIntent, DepositIntentResponse, TransactionResponse, TransactionType},
        messaging::ChannelMessage,
        rpc::RPCRequest,
        rpc_server::{
            AddLiquidityRequest, AddLiquidityResponse, ClaimRewardRequest, ClaimRewardResponse,
            DKGStatusResponse, EnhancedUserRegistrationResponse, GetPeerAddressesRequest,
            GetRewardSolverRequest, GetRewardSolverResponse, HeartbeatResponse,
            LogPartialPubkeysRequest, NodeIdResponse, RequestContext, SolverLiquidityRequest,
            SolverLiquidityResponse, UptimeResponse, UserInfoResponse, UserMpcDepositRequest,
            UserMpcDepositVerifyResponse, UserRegistrationRequest, WithdrawLiquidityRequest,
            WithdrawLiquidityResponse,
        },
        TransactionNetwork,
    },
    user_intent_manager::{checksum_from_any, UserIntentManager},
    utils::transaction::DUST_LIMIT_SATS,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use super::{
    errors::{RpcError, TransactionError},
    utils::{
        convert_src_smallest_to_dst_smallest, fetch_crypto_prices, get_actual_dkg_secret_share,
        normalize_eth_signature, recover_eth_address_secp, wait_for_reward_transaction_ids,
        wait_for_transaction_result, wait_for_withdraw_liquidity_transaction_ids,
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
    U256::from_dec_str(value).map_err(|_| format!("Invalid {asset_label} withdraw amount: {value}"))
}

fn ensure_withdraw_amount_bounds(value: &U256, asset_label: &str) -> Result<(), String> {
    if value.is_zero() {
        return Err(format!(
            "{asset_label} withdraw amount must be greater than zero"
        ));
    }
    if value.bits() > 128 {
        return Err(format!(
            "{asset_label} withdraw amount exceeds supported limit"
        ));
    }
    Ok(())
}

fn enforce_minimum_remaining(
    available: &U256,
    withdraw: &U256,
    min_required: Option<&U256>,
    asset_label: &str,
) -> Result<(), String> {
    let remaining = available.saturating_sub(*withdraw);
    if remaining.is_zero() {
        return Ok(());
    }

    if let Some(min) = min_required {
        if remaining < *min {
            return Err(format!(
                "{asset_label} withdrawal would leave less than minimum required liquidity ({min})"
            ));
        }
    }

    Ok(())
}

fn select_withdraw_amount(
    requested: Option<&String>,
    available: Option<&String>,
    asset_label: &str,
    min_required: Option<&U256>,
) -> Result<Option<String>, String> {
    match (requested, available) {
        (Some(req), Some(avail)) => {
            let req_val = parse_withdraw_amount(req, asset_label)?;
            ensure_withdraw_amount_bounds(&req_val, asset_label)?;
            let avail_val = parse_withdraw_amount(avail, asset_label)?;
            if req_val > avail_val {
                return Err(format!(
                    "{asset_label} withdraw amount exceeds available liquidity"
                ));
            }
            enforce_minimum_remaining(&avail_val, &req_val, min_required, asset_label)?;
            Ok(Some(req.clone()))
        }
        (Some(_), None) => Err(format!(
            "No {asset_label} liquidity available to fulfill withdrawal"
        )),
        (None, Some(avail)) => {
            let avail_val = parse_withdraw_amount(avail, asset_label)?;
            if avail_val.is_zero() {
                return Ok(None);
            }
            ensure_withdraw_amount_bounds(&avail_val, asset_label)?;
            enforce_minimum_remaining(&avail_val, &avail_val, min_required, asset_label)?;
            Ok(Some(avail.clone()))
        }
        (None, None) => Ok(None),
    }
}

fn validate_liquidity_amount(
    requested: Option<&String>,
    asset_label: &str,
) -> Result<Option<String>, String> {
    match requested {
        Some(value) => {
            let parsed = parse_withdraw_amount(value, asset_label)?;
            ensure_withdraw_amount_bounds(&parsed, asset_label)?;
            Ok(Some(value.clone()))
        }
        None => Ok(None),
    }
}

fn withdraw_error_response(
    solver_address: String,
    liquidity_btc: &Option<String>,
    liquidity_tics: &Option<String>,
    req: &WithdrawLiquidityRequest,
    message: String,
    error_message: Option<String>,
) -> WithdrawLiquidityResponse {
    WithdrawLiquidityResponse {
        status: "error".to_string(),
        solver_address,
        liquidity_btc: liquidity_btc.clone(),
        liquidity_tics: liquidity_tics.clone(),
        ethereum_address: req.ethereum_address.clone(),
        btc_address: req.btc_address.clone(),
        tics_withdraw_tx_id: None,
        btc_withdraw_tx_id: None,
        message,
        error_message,
    }
}

async fn maybe_initiate_withdrawal(
    asset_label: &str,
    requested_amount: Option<&String>,
    available_liquidity: Option<&String>,
    destination: Option<&String>,
    min_required: Option<&U256>,
    solver_address: &str,
    liquidity_btc: &Option<String>,
    liquidity_tics: &Option<String>,
    req: &WithdrawLiquidityRequest,
    message_tx: &Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    build_channel_msg: impl Fn(String, String, String) -> ChannelMessage,
    missing_address_msg: &str,
) -> Result<bool, WithdrawLiquidityResponse> {
    let withdraw_amount = select_withdraw_amount(
        requested_amount,
        available_liquidity,
        asset_label,
        min_required,
    )
    .map_err(|msg| {
        withdraw_error_response(
            solver_address.to_string(),
            liquidity_btc,
            liquidity_tics,
            req,
            msg.clone(),
            Some(msg),
        )
    })?;

    let Some(amount_str) = withdraw_amount else {
        return Ok(false);
    };

    let destination_addr = match destination {
        Some(addr) => addr,
        None => {
            return Err(withdraw_error_response(
                solver_address.to_string(),
                liquidity_btc,
                liquidity_tics,
                req,
                missing_address_msg.to_string(),
                Some(missing_address_msg.to_string()),
            ))
        }
    };

    info!(
        "🚰 [WITHDRAW] Initiating {asset_label} withdrawal for solver {} -> {} (amount: {})",
        solver_address, destination_addr, amount_str
    );

    let msg = build_channel_msg(
        solver_address.to_string(),
        destination_addr.clone(),
        amount_str.clone(),
    );
    let tx_sender = message_tx.lock().await;
    if let Err(e) = tx_sender.send(msg).await {
        error!(
            "❌ Failed to dispatch {asset_label} withdraw message for solver {}: {}",
            solver_address, e
        );
        return Err(withdraw_error_response(
            solver_address.to_string(),
            liquidity_btc,
            liquidity_tics,
            req,
            format!("Failed to initiate {asset_label} withdrawal"),
            Some(format!("Network error: {e}")),
        ));
    }

    Ok(true)
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

    // Block user registration while DKG shares are being refreshed
    if dkg_storage.is_refresh_in_progress().await.unwrap_or(false) {
        warn!("⚠️ HTTP: Blocking register_user - shares are getting refreshed");
        let error_response = EnhancedUserRegistrationResponse {
            status: "error".to_string(),
            message: "shares are getting refreshed".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::DkgNotReady("shares are getting refreshed".to_string())
                    .to_error_response(),
            ),
        };
        return Ok(warp::reply::json(&error_response));
    }

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

    // Signature verification - verify that the user controls the Ethereum address
    // This is required to prevent address squatting attacks
    let (signature, message) = match (&request.signature, &request.message) {
        (Some(sig), Some(msg)) => (sig, msg),
        _ => {
            error!("❌ Signature and message are required for user registration");
            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "Signature and message are required for user registration".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(
                    RpcError::InvalidRequest(
                        "Signature and message are required for user registration to prove ownership of the Ethereum address".to_string()
                    )
                    .to_error_response(),
                ),
            };
            return Ok(warp::reply::json(&error_response));
        }
    };

    info!("🔐 Verifying signature for user registration");
    
    // Normalize signature
    let (compact, v) = match normalize_eth_signature(signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ Failed to normalize signature: {}", e);
            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "Invalid signature format".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(
                    RpcError::InvalidRequest(format!("Invalid signature format: {e}"))
                        .to_error_response(),
                ),
            };
            return Ok(warp::reply::json(&error_response));
        }
    };

    // Recover address from signature
    let msg_bytes = message.as_bytes();
    let recovered_address = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
        Ok(addr) => addr,
        Err(e1) => {
            warn!("⚠️ personal_sign recovery failed: {}", e1);
            match recover_eth_address_secp(msg_bytes, &compact, v, false) {
                Ok(addr) => addr,
                Err(e2) => {
                    error!(
                        "❌ Both signature recovery methods failed: personal_sign={}, raw={}",
                        e1, e2
                    );
                    let error_response = EnhancedUserRegistrationResponse {
                        status: "error".to_string(),
                        message: "Failed to recover signature".to_string(),
                        derived_eth_address: None,
                        derived_btc_address: None,
                        error: Some(
                            RpcError::InvalidRequest(format!(
                                "Failed to recover signature: personal_sign={e1}, raw={e2}"
                            ))
                            .to_error_response(),
                        ),
                    };
                    return Ok(warp::reply::json(&error_response));
                }
            }
        }
    };

    // Normalize recovered address for comparison
    let recovered_addr_cs = match checksum_from_any(&recovered_address) {
        Ok(addr) => addr,
        Err(e) => {
            error!("❌ Failed to normalize recovered address: {}", e);
            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "Invalid recovered address".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(
                    RpcError::InvalidRequest(format!("Invalid recovered address: {e}"))
                        .to_error_response(),
                ),
            };
            return Ok(warp::reply::json(&error_response));
        }
    };

    // Verify that recovered address matches the provided ethereum_address
    if recovered_addr_cs.to_lowercase() != addr_cs.to_lowercase() {
        error!(
            "❌ Signature verification failed: recovered address {} does not match provided address {}",
            recovered_addr_cs, addr_cs
        );
        let error_response = EnhancedUserRegistrationResponse {
            status: "error".to_string(),
            message: "Signature verification failed: address mismatch".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest(
                    "Signature verification failed: recovered address does not match provided address".to_string()
                )
                .to_error_response(),
            ),
        };
        return Ok(warp::reply::json(&error_response));
    }

    // Validate message format and timestamp to prevent replay attacks
    // Expected format: "register:{ethereum_address}:{timestamp}"
    let parts: Vec<&str> = message.split(':').collect();
    if parts.len() != 3 || parts[0] != "register" {
        warn!("⚠️ Invalid message format, expected: register:{{address}}:{{timestamp}}");
        let error_response = EnhancedUserRegistrationResponse {
            status: "error".to_string(),
            message: "Invalid message format".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest(
                    "Invalid message format. Expected: register:{address}:{timestamp}".to_string()
                )
                .to_error_response(),
            ),
        };
        return Ok(warp::reply::json(&error_response));
    }

    // Verify the address in the message matches
    let message_addr = match checksum_from_any(parts[1]) {
        Ok(addr) => addr,
        Err(e) => {
            error!("❌ Invalid address in message: {}", e);
            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "Invalid address in message".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(
                    RpcError::InvalidRequest(format!("Invalid address in message: {e}"))
                        .to_error_response(),
                ),
            };
            return Ok(warp::reply::json(&error_response));
        }
    };

    if message_addr.to_lowercase() != addr_cs.to_lowercase() {
        error!(
            "❌ Address in message {} does not match provided address {}",
            message_addr, addr_cs
        );
        let error_response = EnhancedUserRegistrationResponse {
            status: "error".to_string(),
            message: "Address in message does not match provided address".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest(
                    "Address in message does not match provided address".to_string()
                )
                .to_error_response(),
            ),
        };
        return Ok(warp::reply::json(&error_response));
    }

    // Validate timestamp to prevent replay attacks (allow 5 minute window)
    if let Ok(timestamp) = parts[2].parse::<i64>() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let time_diff = (now - timestamp).abs();
        const MAX_TIME_DIFF: i64 = 300; // 5 minutes

        if time_diff > MAX_TIME_DIFF {
            warn!(
                "⚠️ Timestamp validation failed: time difference {} seconds exceeds maximum {} seconds",
                time_diff, MAX_TIME_DIFF
            );
            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "Timestamp validation failed: message expired or invalid".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(
                    RpcError::InvalidRequest(
                        format!("Timestamp validation failed: time difference {} seconds exceeds maximum {} seconds", time_diff, MAX_TIME_DIFF)
                    )
                    .to_error_response(),
                ),
            };
            return Ok(warp::reply::json(&error_response));
        }
    } else {
        warn!("⚠️ Invalid timestamp format in message");
        let error_response = EnhancedUserRegistrationResponse {
            status: "error".to_string(),
            message: "Invalid timestamp format in message".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest("Invalid timestamp format in message".to_string())
                    .to_error_response(),
            ),
        };
        return Ok(warp::reply::json(&error_response));
    }

    info!("✅ Signature verification successful for address: {}", addr_cs);

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
                        warn!(
                            "⚠️ User temporarily missing from registry during address derivation, retrying..."
                        );
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

            // Check if addresses were generated within the timeout
            if final_registration.derived_eth_address.is_none()
                || final_registration.derived_btc_address.is_none()
            {
                error!(
                    "❌ HTTP: Derived addresses not available after {} attempts ({} seconds)",
                    MAX_ATTEMPTS, MAX_ATTEMPTS
                );
                let error_response = EnhancedUserRegistrationResponse {
                    status: "error".to_string(),
                    message: format!(
                        "Derived addresses (ETH/BTC) were not generated within {} seconds. Please try again later.",
                        MAX_ATTEMPTS
                    ),
                    derived_eth_address: final_registration.derived_eth_address,
                    derived_btc_address: final_registration.derived_btc_address,
                    error: Some(
                        RpcError::Timeout(format!(
                            "Derived addresses not generated within {} seconds",
                            MAX_ATTEMPTS
                        ))
                        .to_error_response(),
                    ),
                };
                return Ok(warp::reply::json(&error_response));
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
    // Block deposits while DKG shares are being refreshed
    if dkg_storage.is_refresh_in_progress().await.unwrap_or(false) {
        warn!(
            request_id = %request_context.request_id,
            "⚠️ HTTP: Blocking user_mpc_deposit - shares are getting refreshed"
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
            error_message: Some("shares are getting refreshed".to_string()),
        }));
    }

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

    info!("🧾 HTTP: user_mpc_deposit received");

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
            if let Some(ref vault_to_network_tx) = tx_ids.vault_to_network_tx_id {
                transaction_ids.push(vault_to_network_tx.clone());
            }
        }
    }

    let transaction_type = if transaction_ids.len() == 2 {
        // Both user->network and network->target transactions exist:
        // this is a vault-to-network case (funds are being sent back to the network).
        TransactionType::VaultToNetwork
    } else if transaction_ids.len() == 1 {
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
            vault_to_network_tx_id: tx_mapping
                .as_ref()
                .and_then(|tx| tx.vault_to_network_tx_id.clone()),
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
                                error_message: Some(format!("Invalid signature format: {e}")),
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
                                            "Failed to recover signature: personal_sign={e1}, raw={e2}"
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
                            error_message: Some(format!("Failed to process deposit intent: {e}")),
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
            let error_message = format!("{e:?}");

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

    let intent_hash_hex = hex::encode(intent_hash);
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
                "Transaction processing timeout. Intent hash: {intent_hash_hex}. The transaction may still be processing or may have failed. Please check the status later."
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
                has_tweaked_share: None,
                has_user_group_key: None,
                derived_eth_address: None,
                derived_btc_address: None,
                created_at: None,
                error: Some(
                    RpcError::UserNotFound(format!("User with address {addr_cs} not found"))
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
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("here at handle status!! ");

    let (responder, receiver) = tokio::sync::oneshot::channel();
    {
        let tx_sender = message_tx.lock().await;
        tx_sender
            .send(ChannelMessage::StatusRequest { responder })
            .await
            .map_err(|e| {
                warp::reject::custom(super::errors::RpcError::InternalError(format!(
                    "Failed to request node status: {e}"
                )))
            })?;
    }

    let status = tokio::time::timeout(std::time::Duration::from_secs(5), receiver)
        .await
        .map_err(|_| {
            warp::reject::custom(super::errors::RpcError::Timeout(
                "Timed out waiting for node status".to_string(),
            ))
        })
        .and_then(|res| {
            res.map_err(|e| {
                warp::reject::custom(super::errors::RpcError::InternalError(format!(
                    "Failed to receive node status: {e}"
                )))
            })
        })?;

    Ok(warp::reply::json(&status))
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
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Block manual DKG start while a refresh is in progress
    if dkg_storage.is_refresh_in_progress().await.unwrap_or(false) {
        warn!("⚠️ HTTP: Blocking start_dkg - shares are getting refreshed");
        return Ok(warp::reply::json(&TransactionResponse {
            tx_hash: "".to_string(),
            status: "error".to_string(),
            message: "shares are getting refreshed".to_string(),
        }));
    }

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
                error_message: Some(format!("Invalid address format: {e}")),
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

pub(crate) async fn handle_get_solver_liquidity(
    req: SolverLiquidityRequest,
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🔍 HTTP: get_solver_liquidity request for solver: {}",
        req.solver_address
    );

    if req.solver_address.trim().is_empty() {
        return Ok(warp::reply::json(&SolverLiquidityResponse {
            status: "error".to_string(),
            solver_address: req.solver_address,
            liquidity_btc: None,
            liquidity_tics: None,
            message: "Solver address cannot be empty".to_string(),
            error_message: Some("Solver address is required".to_string()),
        }));
    }

    let normalized_address = match checksum_from_any(&req.solver_address) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("❌ Invalid solver address format: {}", e);
            return Ok(warp::reply::json(&SolverLiquidityResponse {
                status: "error".to_string(),
                solver_address: req.solver_address,
                liquidity_btc: None,
                liquidity_tics: None,
                message: "Invalid solver address format".to_string(),
                error_message: Some(format!("Invalid address format: {e}")),
            }));
        }
    };

    let database = user_intent_manager.get_database();
    let solver_liquidity_key = format!("solver_liquidity:{}", normalized_address.to_lowercase());

    let liquidity_amounts: Option<Vec<String>> =
        match database.get_string::<Vec<String>>(&solver_liquidity_key) {
            Ok(amounts) => amounts,
            Err(e) => {
                warn!("❌ Failed to get solver liquidity from database: {}", e);
                return Ok(warp::reply::json(&SolverLiquidityResponse {
                    status: "error".to_string(),
                    solver_address: normalized_address,
                    liquidity_btc: None,
                    liquidity_tics: None,
                    message: "Failed to fetch solver liquidity".to_string(),
                    error_message: Some(format!("Database error: {e}")),
                }));
            }
        };

    if liquidity_amounts.is_none() {
        warn!(
            "❌ Address {} is not a valid solver (no liquidity entry found)",
            normalized_address
        );
        return Ok(warp::reply::json(&SolverLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address,
            liquidity_btc: None,
            liquidity_tics: None,
            message: "Address is not a valid solver".to_string(),
            error_message: Some("No liquidity entry found for this address".to_string()),
        }));
    }

    let amounts = liquidity_amounts.unwrap();
    let liquidity_btc = amounts.first().and_then(|s| {
        if s.trim().is_empty() || s == "0" {
            None
        } else {
            Some(s.clone())
        }
    });
    let liquidity_tics = amounts.get(1).and_then(|s| {
        if s.trim().is_empty() || s == "0" {
            None
        } else {
            Some(s.clone())
        }
    });

    if liquidity_btc.is_none() && liquidity_tics.is_none() {
        warn!(
            "❌ No liquidity available for solver address: {}",
            normalized_address
        );
        return Ok(warp::reply::json(&SolverLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address,
            liquidity_btc,
            liquidity_tics,
            message: "No liquidity available for solver".to_string(),
            error_message: Some("No liquidity available for solver".to_string()),
        }));
    }

    info!(
        "✅ Stored liquidity for solver {} - BTC: {:?}, TICS: {:?}",
        normalized_address, liquidity_btc, liquidity_tics
    );

    Ok(warp::reply::json(&SolverLiquidityResponse {
        status: "success".to_string(),
        solver_address: normalized_address,
        liquidity_btc,
        liquidity_tics,
        message: "Solver liquidity retrieved successfully".to_string(),
        error_message: None,
    }))
}

pub(crate) async fn handle_claim_reward(
    req: ClaimRewardRequest,
    user_intent_manager: Arc<UserIntentManager>,
    _reward_storage: Arc<RewardStorage>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Block reward claims while DKG shares are being refreshed
    if dkg_storage.is_refresh_in_progress().await.unwrap_or(false) {
        warn!("⚠️ HTTP: Blocking claim_reward - shares are getting refreshed");
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: req.ethereum_address,
            btc_address: req.btc_address,
            reward_btc: None,
            reward_tics: None,
            message: "shares are getting refreshed".to_string(),
            error_message: Some("shares are getting refreshed".to_string()),
            tics_reward_tx_id: None,
            btc_reward_tx_id: None,
        }));
    }

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
                    error_message: Some(format!("Invalid Ethereum address: {e:?}")),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        }
    } else {
        None
    };

    let wants_tics = normalized_eth_address.is_some();
    let wants_btc = req.btc_address.as_ref().is_some();

    if wants_tics && wants_btc {
        let msg = "Only one reward type can be claimed per request. Provide either ethereum_address or btc_address.".to_string();
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: normalized_eth_address,
            btc_address: req.btc_address,
            reward_btc: None,
            reward_tics: None,
            message: msg.clone(),
            error_message: Some(msg),
            tics_reward_tx_id: None,
            btc_reward_tx_id: None,
        }));
    }

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
                error_message: Some(format!("Invalid signature: {e:?}")),
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
                        "Failed to recover signature: personal_sign={e1}, raw={e2}"
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

    let reward_btc = if wants_btc {
        user_intent_manager
            .get_solver_reward_btc(solver_address.as_str())
            .await
            .filter(|v| !v.is_zero())
    } else {
        None
    };
    let reward_tics = if wants_tics {
        user_intent_manager
            .get_solver_reward_tics(solver_address.as_str())
            .await
            .filter(|v| !v.is_zero())
    } else {
        None
    };

    // Check if BTC reward is below dust limit
    if wants_btc {
        if let Some(ref btc_reward) = reward_btc {
            // Convert U256 to u64 for comparison (saturating to avoid overflow)
            let btc_reward_u64 = btc_reward.as_u64();
            if btc_reward_u64 > 0 && btc_reward_u64 < DUST_LIMIT_SATS {
                let msg = format!(
                    "BTC reward {} sats is below Bitcoin dust limit (minimum: {} sats). Transaction would be rejected by Bitcoin nodes.",
                    btc_reward_u64,
                    DUST_LIMIT_SATS
                );
                warn!("❌ {}", msg);
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    ethereum_address: normalized_eth_address,
                    btc_address: req.btc_address,
                    reward_btc: None,
                    reward_tics: None,
                    message: msg.clone(),
                    error_message: Some(msg),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        }
    }

    let reward_btc_str = reward_btc.as_ref().map(|v| v.to_string());
    let reward_tics_str = reward_tics.as_ref().map(|v| v.to_string());

    let previous_tics_tx_id = user_intent_manager
        .get_solver_tics_txn_hash(solver_address.as_str())
        .await;
    let previous_btc_tx_id = user_intent_manager
        .get_solver_btc_txn_hash(solver_address.as_str())
        .await;

    let expect_tics_tx = wants_tics && reward_tics_str.is_some();
    let expect_btc_tx = wants_btc && reward_btc_str.is_some();

    if wants_tics && reward_tics_str.is_none() {
        let msg = "No TICS rewards available to claim".to_string();
        warn!("❌ {}", msg);
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: normalized_eth_address,
            btc_address: req.btc_address,
            reward_btc: None,
            reward_tics: None,
            message: msg.clone(),
            error_message: Some(msg),
            tics_reward_tx_id: None,
            btc_reward_tx_id: None,
        }));
    }

    if wants_btc && reward_btc_str.is_none() {
        let msg = "No BTC rewards available to claim".to_string();
        warn!("❌ {}", msg);
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: normalized_eth_address,
            btc_address: req.btc_address,
            reward_btc: None,
            reward_tics: None,
            message: msg.clone(),
            error_message: Some(msg),
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
            error_message: Some(format!("Network error: {e}")),
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

    let missing_tics_tx = expect_tics_tx && tics_reward_tx_id.is_none();
    let missing_btc_tx = expect_btc_tx && btc_reward_tx_id.is_none();
    if missing_tics_tx || missing_btc_tx {
        let mut missing_networks = Vec::new();
        if missing_tics_tx {
            missing_networks.push("TICS");
        }
        if missing_btc_tx {
            missing_networks.push("BTC");
        }
        let missing_list = missing_networks.join(" & ");
        let msg = format!(
            "Timed out waiting for {missing_list} reward transaction confirmation for solver {solver_address}"
        );
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: normalized_eth_address,
            btc_address: req.btc_address,
            reward_btc: reward_btc_str,
            reward_tics: reward_tics_str,
            message: msg.clone(),
            error_message: Some(msg),
            tics_reward_tx_id,
            btc_reward_tx_id,
        }));
    }

    let success_message = if wants_tics {
        "TICS reward claim processed successfully".to_string()
    } else {
        "BTC reward claim processed successfully".to_string()
    };

    info!(
        "✅ Reward claim processed successfully for solver: {}, reward_type: {}",
        solver_address,
        if wants_tics { "TICS" } else { "BTC" }
    );

    Ok(warp::reply::json(&ClaimRewardResponse {
        status: "success".to_string(),
        ethereum_address: normalized_eth_address,
        btc_address: req.btc_address,
        reward_btc: reward_btc_str,
        reward_tics: reward_tics_str,
        message: success_message,
        error_message: None,
        tics_reward_tx_id,
        btc_reward_tx_id,
    }))
}

pub(crate) async fn handle_withdraw_liquidity(
    req: WithdrawLiquidityRequest,
    user_intent_manager: Arc<UserIntentManager>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Block liquidity withdrawals while DKG shares are being refreshed
    if dkg_storage.is_refresh_in_progress().await.unwrap_or(false) {
        warn!("⚠️ HTTP: Blocking withdraw_liquidity - shares are getting refreshed");
        return Ok(warp::reply::json(&WithdrawLiquidityResponse {
            status: "error".to_string(),
            solver_address: "".to_string(),
            liquidity_btc: None,
            liquidity_tics: None,
            ethereum_address: req.ethereum_address.clone(),
            btc_address: req.btc_address.clone(),
            tics_withdraw_tx_id: None,
            btc_withdraw_tx_id: None,
            message: "shares are getting refreshed".to_string(),
            error_message: Some("shares are getting refreshed".to_string()),
        }));
    }

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
                error_message: Some(format!("Invalid signature: {e:?}")),
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
                        "Failed to recover signature: personal_sign={e1}, raw={e2}"
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
                solver_address,
                liquidity_btc: None,
                liquidity_tics: None,
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Invalid solver address format".to_string(),
                error_message: Some(format!("Invalid address format: {e}")),
            }));
        }
    };

    // Check if address is a valid solver by checking liquidity in database
    let database = user_intent_manager.get_database();
    let solver_liquidity_key = format!("solver_liquidity:{}", normalized_address.to_lowercase());

    let liquidity_amounts: Option<Vec<String>> =
        match database.get_string::<Vec<String>>(&solver_liquidity_key) {
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
                    error_message: Some(format!("Database error: {e}")),
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
    let liquidity_btc_str = amounts.first().and_then(|s| {
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

    // Fetch minimum liquidity thresholds only for the requested asset
    let wants_tics = req.amount_tics.is_some();
    let wants_btc = req.amount_btc.is_some();

    let (minimum_liquidity_tics, minimum_liquidity_btc) = if wants_tics || wants_btc {
        let solver_contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS").unwrap_or_default();
        let solver_contract_rpc = std::env::var("SOLVER_CONTRACT_RPC_URL").unwrap_or_default();
        let solver_contract_chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
            .unwrap_or_else(|_| "9029".to_string())
            .parse::<u64>()
            .unwrap_or(9029);

        if solver_contract_address.trim().is_empty() || solver_contract_rpc.trim().is_empty() {
            let msg = "Solver contract configuration missing".to_string();
            return Ok(warp::reply::json(&withdraw_error_response(
                normalized_address.clone(),
                &liquidity_btc_str,
                &liquidity_tics_str,
                &req,
                msg.clone(),
                Some(msg),
            )));
        }

        let parsed_contract_address = match solver_contract_address.parse::<Address>() {
            Ok(addr) => addr,
            Err(e) => {
                let msg = format!("Invalid solver contract address: {e}");
                return Ok(warp::reply::json(&withdraw_error_response(
                    normalized_address.clone(),
                    &liquidity_btc_str,
                    &liquidity_tics_str,
                    &req,
                    msg.clone(),
                    Some(msg),
                )));
            }
        };

        let contract_config = ContractConfig {
            rpc_url: solver_contract_rpc,
            contract_address: parsed_contract_address,
            chain_id: solver_contract_chain_id,
        };

        let contract_client = match ContractClient::new(contract_config.clone()) {
            Ok(client) => client,
            Err(e) => {
                let msg = format!("Failed to create solver contract client: {e}");
                return Ok(warp::reply::json(&withdraw_error_response(
                    normalized_address.clone(),
                    &liquidity_btc_str,
                    &liquidity_tics_str,
                    &req,
                    msg.clone(),
                    Some(msg),
                )));
            }
        };

        let solver_contract =
            match SolverManagerContract::new(&contract_config, contract_client.provider()) {
                Ok(contract) => contract,
                Err(e) => {
                    let msg = format!("Failed to initialize solver contract: {e}");
                    return Ok(warp::reply::json(&withdraw_error_response(
                        normalized_address.clone(),
                        &liquidity_btc_str,
                        &liquidity_tics_str,
                        &req,
                        msg.clone(),
                        Some(msg),
                    )));
                }
            };

        let min_tics = if wants_tics {
            Some(match solver_contract.get_minimum_liquidity_tics().await {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Failed to fetch minimum TICS liquidity: {e}");
                    return Ok(warp::reply::json(&withdraw_error_response(
                        normalized_address.clone(),
                        &liquidity_btc_str,
                        &liquidity_tics_str,
                        &req,
                        msg.clone(),
                        Some(msg),
                    )));
                }
            })
        } else {
            None
        };

        let min_btc = if wants_btc {
            Some(match solver_contract.get_minimum_liquidity_btc().await {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Failed to fetch minimum BTC liquidity: {e}");
                    return Ok(warp::reply::json(&withdraw_error_response(
                        normalized_address.clone(),
                        &liquidity_btc_str,
                        &liquidity_tics_str,
                        &req,
                        msg.clone(),
                        Some(msg),
                    )));
                }
            })
        } else {
            None
        };

        (min_tics, min_btc)
    } else {
        (None, None)
    };

    let withdraw_tics_amount: Option<String> = if wants_tics {
        match select_withdraw_amount(
            req.amount_tics.as_ref(),
            liquidity_tics_str.as_ref(),
            "TICS",
            minimum_liquidity_tics.as_ref(),
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
        }
    } else {
        // Caller did not request TICS withdrawal
        None
    };

    let withdraw_btc_amount: Option<String> = if wants_btc {
        match select_withdraw_amount(
            req.amount_btc.as_ref(),
            liquidity_btc_str.as_ref(),
            "BTC",
            minimum_liquidity_btc.as_ref(),
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
        }
    } else {
        // Caller did not request BTC withdrawal
        None
    };

    if withdraw_tics_amount.is_some() && withdraw_btc_amount.is_some() {
        let msg =
            "Only one liquidity type can be withdrawn per request. Provide amount_tics or amount_btc."
                .to_string();
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

    if withdraw_tics_amount.is_some() {
        let maybe_initiated = maybe_initiate_withdrawal(
            "TICS",
            withdraw_tics_amount.as_ref(),
            liquidity_tics_str.as_ref(),
            req.ethereum_address.as_ref(),
            minimum_liquidity_tics.as_ref(),
            &normalized_address,
            &liquidity_btc_str,
            &liquidity_tics_str,
            &req,
            &message_tx,
            |solver, dest, amount| ChannelMessage::WithdrawLiquidity {
                solver_address: solver,
                btc_address: None,
                eth_address: Some(dest),
                amount_btc: None,
                amount_tics: Some(amount),
                transaction_type: "withdraw_liquidity".to_string(),
            },
            "Ethereum address is required for TICS withdrawal",
        )
        .await;

        match maybe_initiated {
            Ok(flag) => initiated_tics = flag,
            Err(resp) => return Ok(warp::reply::json(&resp)),
        }
    }

    if withdraw_btc_amount.is_some() {
        let maybe_initiated = maybe_initiate_withdrawal(
            "BTC",
            withdraw_btc_amount.as_ref(),
            liquidity_btc_str.as_ref(),
            req.btc_address.as_ref(),
            minimum_liquidity_btc.as_ref(),
            &normalized_address,
            &liquidity_btc_str,
            &liquidity_tics_str,
            &req,
            &message_tx,
            |solver, dest, amount| ChannelMessage::WithdrawLiquidity {
                solver_address: solver,
                btc_address: Some(dest),
                eth_address: None,
                amount_btc: Some(amount),
                amount_tics: None,
                transaction_type: "withdraw_liquidity".to_string(),
            },
            "BTC address is required for BTC withdrawal",
        )
        .await;

        match maybe_initiated {
            Ok(flag) => initiated_btc = flag,
            Err(resp) => return Ok(warp::reply::json(&resp)),
        }
    }

    // Get previous transaction IDs to detect new ones
    // Use remove_liquidity storage (not the shared tics/btc txn hash to avoid overlap with reward transactions)
    let previous_tics_tx_id = user_intent_manager
        .get_solver_remove_liquidity_txn_hash(normalized_address.as_str(), TransactionNetwork::TICS)
        .await
        .ok()
        .flatten();
    let previous_btc_tx_id = user_intent_manager
        .get_solver_remove_liquidity_txn_hash(normalized_address.as_str(), TransactionNetwork::BTC)
        .await
        .ok()
        .flatten();

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

    let missing_tics_tx = initiated_tics && tics_withdraw_tx_id.is_none();
    let missing_btc_tx = initiated_btc && btc_withdraw_tx_id.is_none();
    if missing_tics_tx || missing_btc_tx {
        let mut missing_networks = Vec::new();
        if missing_tics_tx {
            missing_networks.push("TICS");
        }
        if missing_btc_tx {
            missing_networks.push("BTC");
        }
        let missing_list = missing_networks.join(" & ");
        let msg = format!(
            "Timed out waiting for {missing_list} withdraw liquidity transaction confirmation for solver {normalized_address}"
        );
        return Ok(warp::reply::json(&WithdrawLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address,
            liquidity_btc: liquidity_btc_str,
            liquidity_tics: liquidity_tics_str,
            ethereum_address: req.ethereum_address.clone(),
            btc_address: req.btc_address.clone(),
            tics_withdraw_tx_id,
            btc_withdraw_tx_id,
            message: msg.clone(),
            error_message: Some(msg),
        }));
    }

    let message = if initiated_tics {
        "Liquidity withdrawal initiated for TICS".to_string()
    } else if initiated_btc {
        "Liquidity withdrawal initiated for BTC".to_string()
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

pub(crate) async fn handle_add_liquidity(
    req: AddLiquidityRequest,
    _user_intent_manager: Arc<UserIntentManager>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Block add_liquidity while DKG shares are being refreshed
    if dkg_storage.is_refresh_in_progress().await.unwrap_or(false) {
        warn!("⚠️ HTTP: Blocking add_liquidity - shares are getting refreshed");
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            solver_address: "".to_string(),
            solver_id: req.solver_id.clone(),
            amount_tics: req.amount_tics.clone(),
            amount_btc: req.amount_btc.clone(),
            message: "shares are getting refreshed".to_string(),
            error_message: Some("shares are getting refreshed".to_string()),
        }));
    }

    info!(
        "💧 HTTP: add_liquidity request with message: {}, solver_id: {}",
        req.message, req.solver_id
    );

    let normalized_solver_id = req.solver_id.trim().to_string();
    if normalized_solver_id.is_empty() {
        let msg = "solver_id is required".to_string();
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            solver_address: "".to_string(),
            solver_id: normalized_solver_id,
            amount_tics: req.amount_tics.clone(),
            amount_btc: req.amount_btc.clone(),
            message: msg.clone(),
            error_message: Some(msg),
        }));
    }

    let requested_tics = match validate_liquidity_amount(req.amount_tics.as_ref(), "TICS") {
        Ok(value) => value,
        Err(msg) => {
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                solver_address: "".to_string(),
                solver_id: normalized_solver_id.clone(),
                amount_tics: req.amount_tics.clone(),
                amount_btc: req.amount_btc.clone(),
                message: msg.clone(),
                error_message: Some(msg),
            }));
        }
    };
    let requested_btc = match validate_liquidity_amount(req.amount_btc.as_ref(), "BTC") {
        Ok(value) => value,
        Err(msg) => {
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                solver_address: "".to_string(),
                solver_id: normalized_solver_id.clone(),
                amount_tics: req.amount_tics.clone(),
                amount_btc: req.amount_btc.clone(),
                message: msg.clone(),
                error_message: Some(msg),
            }));
        }
    };

    if requested_tics.is_none() && requested_btc.is_none() {
        let msg = "At least one of amount_tics or amount_btc must be provided".to_string();
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            solver_address: "".to_string(),
            solver_id: normalized_solver_id.clone(),
            amount_tics: requested_tics,
            amount_btc: requested_btc,
            message: msg.clone(),
            error_message: Some(msg),
        }));
    }

    if requested_tics.is_some() && requested_btc.is_some() {
        let msg =
            "Only one liquidity type can be added per request. Provide amount_tics or amount_btc."
                .to_string();
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            solver_address: "".to_string(),
            solver_id: normalized_solver_id.clone(),
            amount_tics: requested_tics,
            amount_btc: requested_btc,
            message: msg.clone(),
            error_message: Some(msg),
        }));
    }

    let (compact, v) = match normalize_eth_signature(&req.signature) {
        Ok(t) => t,
        Err(e) => {
            let err_msg = format!("Invalid signature: {e:?}");
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                solver_address: "".to_string(),
                solver_id: normalized_solver_id,
                amount_tics: requested_tics,
                amount_btc: requested_btc,
                message: "Invalid signature format".to_string(),
                error_message: Some(err_msg),
            }));
        }
    };

    let msg_bytes = req.message.as_bytes();
    let solver_address = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
        Ok(addr) => addr,
        Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
            Ok(addr) => addr,
            Err(e2) => {
                let err_msg = format!("Failed to recover signature: personal_sign={e1}, raw={e2}");
                return Ok(warp::reply::json(&AddLiquidityResponse {
                    status: "error".to_string(),
                    solver_address: "".to_string(),
                    solver_id: normalized_solver_id,
                    amount_tics: requested_tics,
                    amount_btc: requested_btc,
                    message: "Failed to recover signature".to_string(),
                    error_message: Some(err_msg),
                }));
            }
        },
    };

    let normalized_address = match checksum_from_any(&solver_address) {
        Ok(addr) => addr,
        Err(e) => {
            let err_msg = format!("Invalid solver address format: {e}");
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                solver_address,
                solver_id: normalized_solver_id,
                amount_tics: requested_tics,
                amount_btc: requested_btc,
                message: "Invalid solver address format".to_string(),
                error_message: Some(err_msg),
            }));
        }
    };

    let solver_contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS").unwrap_or_default();
    let solver_contract_rpc = std::env::var("SOLVER_CONTRACT_RPC_URL").unwrap_or_default();
    let solver_contract_chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
        .unwrap_or_else(|_| "9029".to_string())
        .parse::<u64>()
        .unwrap_or(9029);

    if solver_contract_address.trim().is_empty() || solver_contract_rpc.trim().is_empty() {
        let msg = "Solver contract configuration missing".to_string();
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address.clone(),
            solver_id: normalized_solver_id,
            amount_tics: requested_tics,
            amount_btc: requested_btc,
            message: msg.clone(),
            error_message: Some(msg),
        }));
    }

    let parsed_contract_address = match solver_contract_address.parse::<Address>() {
        Ok(addr) => addr,
        Err(e) => {
            let msg = format!("Invalid solver contract address: {e}");
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                solver_id: normalized_solver_id,
                amount_tics: requested_tics,
                amount_btc: requested_btc,
                message: msg.clone(),
                error_message: Some(msg),
            }));
        }
    };

    let contract_config = ContractConfig {
        rpc_url: solver_contract_rpc,
        contract_address: parsed_contract_address,
        chain_id: solver_contract_chain_id,
    };

    let contract_client = match ContractClient::new(contract_config.clone()) {
        Ok(client) => client,
        Err(e) => {
            let msg = format!("Failed to create solver contract client: {e}");
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                solver_id: normalized_solver_id,
                amount_tics: requested_tics,
                amount_btc: requested_btc,
                message: msg.clone(),
                error_message: Some(msg),
            }));
        }
    };

    let solver_contract =
        match SolverManagerContract::new(&contract_config, contract_client.provider()) {
            Ok(contract) => contract,
            Err(e) => {
                let msg = format!("Failed to initialize solver contract: {e}");
                return Ok(warp::reply::json(&AddLiquidityResponse {
                    status: "error".to_string(),
                    solver_address: normalized_address.clone(),
                    solver_id: normalized_solver_id,
                    amount_tics: requested_tics,
                    amount_btc: requested_btc,
                    message: msg.clone(),
                    error_message: Some(msg),
                }));
            }
        };

    let solver_address_onchain = match solver_contract
        .get_solver_evm_address(&normalized_solver_id)
        .await
    {
        Ok(addr) => addr,
        Err(e) => {
            let msg = format!("Solver not found for solver_id {normalized_solver_id}: {e}");
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                solver_id: normalized_solver_id,
                amount_tics: requested_tics,
                amount_btc: requested_btc,
                message: "Invalid solver_id".to_string(),
                error_message: Some(msg),
            }));
        }
    };

    if solver_address_onchain == Address::zero() {
        let msg = format!("Solver {normalized_solver_id} is not registered on contract");
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address.clone(),
            solver_id: normalized_solver_id,
            amount_tics: requested_tics,
            amount_btc: requested_btc,
            message: "Invalid solver_id".to_string(),
            error_message: Some(msg),
        }));
    }

    let contract_solver_address = format!("{solver_address_onchain:#x}");
    if contract_solver_address.to_lowercase() != normalized_address.to_lowercase() {
        let msg = format!(
            "Solver address mismatch: signature {normalized_address}, contract {contract_solver_address}"
        );
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address.clone(),
            solver_id: normalized_solver_id,
            amount_tics: requested_tics,
            amount_btc: requested_btc,
            message: "Invalid solver (address mismatch)".to_string(),
            error_message: Some(msg),
        }));
    }

    // Generate a unique request ID using timestamp + solver_id
    let request_id = {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}_{}", timestamp, normalized_solver_id)
    };

    let channel_msg = ChannelMessage::AddLiquidity {
        solver_address: normalized_address.clone(),
        solver_id: normalized_solver_id.clone(),
        amount_btc: requested_btc.clone(),
        amount_tics: requested_tics.clone(),
        request_id,
    };

    let tx_sender = message_tx.lock().await;
    if let Err(e) = tx_sender.send(channel_msg).await {
        let err_msg = format!("Network error: {e}");
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address,
            solver_id: normalized_solver_id,
            amount_tics: requested_tics,
            amount_btc: requested_btc,
            message: "Failed to dispatch add liquidity request".to_string(),
            error_message: Some(err_msg),
        }));
    }

    info!(
        "✅ add_liquidity accepted for solver {} (solver_id: {})",
        normalized_address, normalized_solver_id
    );

    let success_msg = if requested_tics.is_some() {
        "Add liquidity request submitted for TICS.".to_string()
    } else {
        "Add liquidity request submitted for BTC.".to_string()
    };

    Ok(warp::reply::json(&AddLiquidityResponse {
        status: "success".to_string(),
        solver_address: normalized_address,
        solver_id: normalized_solver_id,
        amount_tics: requested_tics,
        amount_btc: requested_btc,
        message: success_msg,
        error_message: None,
    }))
}

/// Log partial public keys for all users for a specific peer
pub(crate) async fn handle_log_partial_pubkeys(
    request: crate::types::rpc_server::LogPartialPubkeysRequest,
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🔑 [RPC] Logging partial pubkeys for peer: {}",
        request.peer_id
    );

    // Get network share pubkey
    let network_share_pubkey = match dkg_storage
        .get_network_share_pubkey(&request.peer_id)
        .await
    {
        Ok(Some(pubkey)) => {
            let pubkey_bytes = pubkey.to_affine().to_encoded_point(true);
            Some(hex::encode(pubkey_bytes.as_bytes()))
        }
        Ok(None) => {
            warn!("⚠️ [RPC] Network share pubkey not found for peer: {}", request.peer_id);
            None
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get network share pubkey: {}", e);
            None
        }
    };

    // Get vault share pubkey
    let vault_share_pubkey = match dkg_storage
        .get_vault_share_pubkey(&request.peer_id)
        .await
    {
        Ok(Some(pubkey)) => {
            let pubkey_bytes = pubkey.to_affine().to_encoded_point(true);
            Some(hex::encode(pubkey_bytes.as_bytes()))
        }
        Ok(None) => {
            warn!("⚠️ [RPC] Vault share pubkey not found for peer: {}", request.peer_id);
            None
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get vault share pubkey: {}", e);
            None
        }
    };

    // Get all user share pubkeys
    let user_share_pubkeys = match dkg_storage
        .get_all_user_share_pubkeys_for_peer(&request.peer_id)
        .await
    {
        Ok(user_pubkeys) => {
            user_pubkeys
                .into_iter()
                .map(|(user_addr, pubkey)| {
                    let pubkey_bytes = pubkey.to_affine().to_encoded_point(true);
                    crate::types::rpc_server::UserSharePubkeyInfo {
                        user_eth_address: user_addr,
                        share_pubkey: hex::encode(pubkey_bytes.as_bytes()),
                    }
                })
                .collect()
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get user share pubkeys: {}", e);
            Vec::new()
        }
    };

    // Log all the information
    info!("🔑 [RPC] === Partial Pubkeys for Peer: {} ===", request.peer_id);
    if let Some(ref network_pubkey) = network_share_pubkey {
        info!("  📍 Network Share Pubkey: 0x{}", network_pubkey);
    }
    if let Some(ref vault_pubkey) = vault_share_pubkey {
        info!("  📍 Vault Share Pubkey: 0x{}", vault_pubkey);
    }
    info!("  📍 User Share Pubkeys ({} users):", user_share_pubkeys.len());
    for user_info in &user_share_pubkeys {
        info!(
            "     User: {} -> Pubkey: 0x{}",
            user_info.user_eth_address, user_info.share_pubkey
        );
    }
    info!("✅ [RPC] === Finished logging partial pubkeys ===");

    let peer_id = request.peer_id.clone();
    let user_count = user_share_pubkeys.len();
    Ok(warp::reply::json(&crate::types::rpc_server::LogPartialPubkeysResponse {
        status: "success".to_string(),
        peer_id: peer_id.clone(),
        network_share_pubkey,
        vault_share_pubkey,
        user_share_pubkeys: user_share_pubkeys.clone(),
        message: format!(
            "Logged partial pubkeys for peer {} ({} user share pubkeys)",
            peer_id, user_count
        ),
        error_message: None,
    }))
}

/// Get network and vault addresses (TICS/ETH and BTC) for a specific peer
pub(crate) async fn handle_get_peer_addresses(
    request: crate::types::rpc_server::GetPeerAddressesRequest,
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "📍 [RPC] Getting addresses for peer: {}",
        request.peer_id
    );

    // Get network share pubkey and derive addresses
    let network_addresses = match dkg_storage
        .get_network_share_pubkey(&request.peer_id)
        .await
    {
        Ok(Some(pubkey)) => {
            let eth_addr = crate::utils::get_eth_address_from_group_key(pubkey);
            let btc_addr = crate::utils::get_btc_address_from_group_key(pubkey);
            Some(crate::types::rpc_server::AddressInfo {
                eth_address: eth_addr,
                btc_address: btc_addr,
            })
        }
        Ok(None) => {
            warn!("⚠️ [RPC] Network share pubkey not found for peer: {}", request.peer_id);
            None
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get network share pubkey: {}", e);
            None
        }
    };

    // Get vault share pubkey and derive addresses
    let vault_addresses = match dkg_storage
        .get_vault_share_pubkey(&request.peer_id)
        .await
    {
        Ok(Some(pubkey)) => {
            let eth_addr = crate::utils::get_eth_address_from_group_key(pubkey);
            let btc_addr = crate::utils::get_btc_address_from_group_key(pubkey);
            Some(crate::types::rpc_server::AddressInfo {
                eth_address: eth_addr,
                btc_address: btc_addr,
            })
        }
        Ok(None) => {
            warn!("⚠️ [RPC] Vault share pubkey not found for peer: {}", request.peer_id);
            None
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get vault share pubkey: {}", e);
            None
        }
    };

    // Log the addresses
    if let Some(ref net_addrs) = network_addresses {
        info!(
            "📍 [RPC] Peer {} - Network Addresses: ETH={}, BTC={}",
            request.peer_id, net_addrs.eth_address, net_addrs.btc_address
        );
    }
    if let Some(ref vault_addrs) = vault_addresses {
        info!(
            "📍 [RPC] Peer {} - Vault Addresses: ETH={}, BTC={}",
            request.peer_id, vault_addrs.eth_address, vault_addrs.btc_address
        );
    }

    let peer_id = request.peer_id.clone();
    Ok(warp::reply::json(&crate::types::rpc_server::GetPeerAddressesResponse {
        status: "success".to_string(),
        peer_id: peer_id.clone(),
        network_addresses,
        vault_addresses,
        message: format!("Retrieved addresses for peer {}", peer_id),
        error_message: None,
    }))
}

