use std::{sync::Arc, time::Instant};

use ethers::types::{Address, U256};
use hex;
use serde_json;
use sha3::{Digest, Keccak256};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

use crate::rpc_server::utils::get_actual_dkg_secret_share;
use crate::{
    contract::{ContractClient, ContractConfig, SolverManagerContract},
    database::DkgStorage,
    types::{
        intent::{DepositIntent, DepositIntentResponse, TransactionType},
        messaging::ChannelMessage,
        rpc_server::{
            AddLiquidityRequest, AddLiquidityResponse, ClaimRewardRequest, ClaimRewardResponse,
            DKGStatusResponse, EnhancedUserRegistrationResponse, GetSolverRewardsRequest,
            GetSolverRewardsResponse, HeartbeatResponse, IntentDetailsResponse, IntentsSolvedCountResponse,
            NodeIdResponse, PendingClaimRewardRequest, PendingIntentsCountResponse, PendingWithdrawRequest,
            RequestContext,
            SolverLiquidityRequest, SolverLiquidityResponse, UnclaimedRewardEntry, UptimeResponse,
            UserCountResponse, UserInfoResponse,
            UserMpcDepositRequest, UserMpcDepositVerifyResponse, UserRegistrationRequest,
            WithdrawLiquidityRequest, WithdrawLiquidityResponse,
        },
        IntentStatus,
    },
    user_intent_manager::{checksum_from_any, UserIntentManager},
};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use super::{
    errors::{RpcError, TransactionError},
    utils::{normalize_eth_signature, recover_eth_address_secp},
};

pub(crate) async fn handle_deposit_intent(
    intent: DepositIntent,
    user_eth_address: Option<String>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    transaction_type: TransactionType,
    _dkg_storage: Arc<DkgStorage>,
    signature: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📝 HTTP: Received deposit intent request");
    if let Some(addr) = &user_eth_address {
        info!("📝 HTTP: User eth address provided for signing: {}", addr);
    }
    // Parse string amount into u128 for internal processing
    let parsed_amount = intent.amount.parse::<u128>().map_err(|_| {
        warp::reject::custom(RpcError::InvalidRequest(format!(
            "Invalid deposit amount: {}",
            intent.amount
        )))
    })?;

   
    let required_amount_u128 = parsed_amount + (parsed_amount / 20);

    let intent_id = format!("intent-{}", Uuid::new_v4());
    let deposit_intent_msg = ChannelMessage::DepositIntent {
        intent: intent.clone(),
        intent_id: intent_id.clone(),
        user_eth_address: user_eth_address.as_ref().map(|s| s.clone()).unwrap_or_else(|| "unknown".to_string()),
        transaction_type: transaction_type.clone(),
        amount: required_amount_u128,
        signature,
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
                    "Invalid message format. Expected: register:{address}:{timestamp}".to_string(),
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
                    "Address in message does not match provided address".to_string(),
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

    info!(
        "✅ Signature verification successful for address: {}",
        addr_cs
    );

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
            intent_hash: "".to_string(),
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
                intent_hash: "".to_string(),
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

    // CRITICAL: Reject duplicate intent hash immediately - do no further processing (no signature verify, no user lookup, no channel send).
    if user_intent_manager.get_intent(&intent_hash_hex).await.is_some() {
        warn!(
            request_id = %request_context.request_id,
            intent_hash = %intent_hash_hex,
            "⚠️ HTTP: Rejecting deposit - intent hash already exists (duplicate); no processing"
        );
        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            intent_hash: intent_hash_hex.clone(),
            error_message: Some("Intent hash already exists - this deposit has already been processed".to_string()),
        }));
    }

    // CRITICAL: Signature is now mandatory for UserToVault deposits
    let signature = match &req.signature {
        Some(sig) => sig,
        None => {
            warn!(
                request_id = %request_context.request_id,
                intent_hash = %intent_hash_hex,
                "⚠️ HTTP: Rejecting deposit - signature is required"
            );
            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                status: "error".to_string(),
                intent_hash: intent_hash_hex.clone(),
                error_message: Some("Signature is required for UserToVault deposits".to_string()),
            }));
        }
    };

    // Only support UserToVault transaction type
    let transaction_type = TransactionType::UserToVault;

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
            // Signature is already validated above, so we can safely unwrap
            {
                    info!("No existing user found for intent hash, but signature is present in the request.");
                    let (compact, v) = match normalize_eth_signature(signature) {
                        Ok(t) => t,
                        Err(e) => {
                            warn!("❌ Failed to normalize signature: {}", e);
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                intent_hash: intent_hash_hex.clone(),
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
                                        intent_hash: intent_hash_hex.clone(),
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
                                intent_hash: intent_hash_hex.clone(),
                                error_message: Some(
                                    "No user registration found for signer address.".to_string(),
                                ),
                            }));
                        }
                    };
                    let intent_hash_bytes = intent_hash.to_vec();
                    // Store intent hash directly in the local user intent manager instead of
                    // broadcasting it via ChannelMessage::IntentHash / gossipsub.
                    if let Err(e) = user_intent_manager
                        .store_intent_hash(intent_hash_bytes.clone(), &signer, &req.msg)
                        .await
                    {
                        error!("❌ Failed to store intent hash in user intent manager: {}", e);
                        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                            status: "error".to_string(),
                            intent_hash: intent_hash_hex.clone(),
                            error_message: Some(format!("Failed to process deposit intent: {e}")),
                        }));
                    }

                    info!("✅ Stored intent hash for user: {}", signer);

                    user_reg
            }
        }
    };

    // UserToVault always requires user_eth_address
    let user_eth_address = user_registration.ethereum_address.clone();

    // For UserToVault, transaction confirmation would be on source chain
    if let Some(ref tx_id) = req.tx_id {
        let source_chain = req.msg.source_chain.to_lowercase();
        info!(
            "🔎 Would check tx {} confirmation on chain {} (functionality disabled)",
            tx_id, source_chain
        );
    }

    match handle_deposit_intent(
        req.msg.clone(),
        Some(user_eth_address),
        message_tx,
        transaction_type,
        dkg_storage.clone(),
        req.signature.clone(),
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
                intent_hash: intent_hash_hex.clone(),
                error_message: Some(error_message),
            }));
        }
    }

    let intent_hash_hex = hex::encode(intent_hash);
    info!(
        "✅ Deposit intent submitted successfully. Intent hash: {} (use this to fetch intent details later)",
        intent_hash_hex
    );
    Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
        status: "success".to_string(),
        intent_hash: intent_hash_hex,
        error_message: None,
    }))
}

/// Get intent details by intent hash. Database-stored error message is stripped and not returned.
pub(crate) async fn handle_get_intent_details(
    intent_hash: String,
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let intent_hash = intent_hash.trim();
    if intent_hash.is_empty() {
        return Ok(warp::reply::json(&IntentDetailsResponse {
            status: "error".to_string(),
            intent_hash: "".to_string(),
            intent: None,
            intent_status: None,
            user_to_network_tx_id: None,
            network_to_target_tx_id: None,
            final_solver_id: None,
            created_at: None,
            updated_at: None,
            error_message: Some("intent_hash is required".to_string()),
        }));
    }
    let intent = user_intent_manager.get_intent(intent_hash).await;
    let tx_ids = user_intent_manager.get_intent_transaction_ids(intent_hash).await;
    let intent_status = user_intent_manager
        .get_user_by_intent_hash(intent_hash)
        .await
        .and_then(|u| u.intent_hashes.get(intent_hash).cloned())
        .map(|s| format!("{:?}", s));
    match intent {
        None => {
            info!("❌ HTTP: Intent not found: {}", intent_hash);
            Ok(warp::reply::json(&IntentDetailsResponse {
                status: "not_found".to_string(),
                intent_hash: intent_hash.to_string(),
                intent: None,
                intent_status: None,
                user_to_network_tx_id: None,
                network_to_target_tx_id: None,
                final_solver_id: None,
                created_at: None,
                updated_at: None,
                error_message: Some("Intent not found".to_string()),
            }))
        }
        Some(intent) => {
            let (user_to_network_tx_id, network_to_target_tx_id, final_solver_id, created_at, updated_at) =
                match &tx_ids {
                    Some(ids) => (
                        ids.user_to_network_tx_id.clone(),
                        ids.network_to_target_tx_id.clone(),
                        ids.final_solver_id.clone(),
                        Some(ids.created_at.to_rfc3339()),
                        Some(ids.updated_at.to_rfc3339()),
                    ),
                    None => (None, None, None, None, None),
                };
            Ok(warp::reply::json(&IntentDetailsResponse {
                status: "success".to_string(),
                intent_hash: intent_hash.to_string(),
                intent: Some(intent),
                intent_status,
                user_to_network_tx_id,
                network_to_target_tx_id,
                final_solver_id,
                created_at,
                updated_at,
                error_message: None,
            }))
        }
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

pub(crate) async fn handle_get_node_info(
    dkg_storage: Arc<DkgStorage>,
    node_id: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📊 HTTP: Received node info request");

    let dkg_status = if dkg_storage.is_initial_dkg_complete().await.unwrap_or(false) {
        "Completed"
    } else {
        "Pending"
    };

    let peer_indices = dkg_storage.get_all_peer_indices().ok();
    let peer_count = peer_indices.as_ref().map(|p| p.len()).unwrap_or(0);

    info!(
        "✅ HTTP: Node info: peers={}, dkg={}",
        peer_count, dkg_status
    );

    Ok(warp::reply::json(&serde_json::json!({
        "node_id": node_id,
        "status": "active",
        "dkg_status": dkg_status,
        "peer_count": peer_count,
        "peers": peer_indices.unwrap_or_default(),
        "capabilities": {
            "signing": true,
            "vrf": true,
            "upgradeable": true
        }
    })))
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

/// Returns the total count of intents with status Solved.
/// GET /intents_solved_count
pub(crate) async fn handle_get_intents_solved_count(
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let intents = user_intent_manager
        .get_intents_by_status_global(IntentStatus::Solved)
        .await;
    let count = intents.len() as u64;
    info!("📊 HTTP: intents_solved_count = {}", count);
    Ok(warp::reply::json(&IntentsSolvedCountResponse { count }))
}

/// Returns the count of intents with status Pending or Batched (treated as pending intents).
/// GET /pending_intents_count
pub(crate) async fn handle_get_pending_intents_count(
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let pending = user_intent_manager
        .get_intents_by_status_global(IntentStatus::Pending)
        .await;
    let batched = user_intent_manager
        .get_intents_by_status_global(IntentStatus::Batched)
        .await;
    let count = (pending.len() + batched.len()) as u64;
    info!("📊 HTTP: pending_intents_count = {} (Pending: {}, Batched: {})", count, pending.len(), batched.len());
    Ok(warp::reply::json(&PendingIntentsCountResponse { count }))
}

/// Returns the count of successfully registered users.
/// GET /user_count
pub(crate) async fn handle_get_user_count(
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let users = user_intent_manager.get_all_users().await;
    let count = users.len() as u64;
    info!("📊 HTTP: user_count = {}", count);
    Ok(warp::reply::json(&UserCountResponse {
        status: "success".to_string(),
        count,
        message: format!("{} users successfully registered", count),
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

/// Fetch solver liquidity directly from the on-chain SolverManager contract only (no DB).
/// Uses SOLVER_CONTRACT_ADDRESS, SOLVER_CONTRACT_RPC_URL, SOLVER_CONTRACT_CHAIN_ID.
/// Returns (liquidity_btc, liquidity_tics) as decimal strings if non-zero.
async fn fetch_solver_liquidity_from_contract(
    normalized_address: &str,
) -> Result<(Option<String>, Option<String>), String> {
    let rpc_url = std::env::var("SOLVER_CONTRACT_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
    let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse::<u64>()
        .unwrap_or(1);

    if contract_address == "0x0000000000000000000000000000000000000000" {
        return Err("Solver contract address not configured".to_string());
    }

    let contract_addr = contract_address
        .parse::<Address>()
        .map_err(|e| format!("Invalid solver contract address: {e}"))?;

    let config = ContractConfig {
        rpc_url: rpc_url.clone(),
        contract_address: contract_addr,
        chain_id,
    };

    let client =
        ContractClient::new(config.clone()).map_err(|e| format!("Failed to create contract client: {e}"))?;

    let solver_contract = SolverManagerContract::new(&config, client.provider())
        .map_err(|e| format!("Failed to create solver contract interface: {e}"))?;

    let solver_addr = normalized_address
        .parse::<Address>()
        .map_err(|e| format!("Invalid solver EVM address {normalized_address}: {e}"))?;

    // Resolve solver ID from EVM address (contract only; no DB)
    let solver_id = solver_contract
        .get_solver_id(solver_addr)
        .await
        .map_err(|e| format!("Failed to get solver ID: {e}"))?;

    if solver_id.trim().is_empty() {
        return Err("Address is not a registered solver on the contract".to_string());
    }

    // Fetch all chain amounts for this solver from contract
    let amounts = solver_contract
        .get_all_chain_amounts(&solver_id)
        .await
        .map_err(|e| format!("Failed to get solver chain amounts: {e}"))?;

    if amounts.is_empty() {
        return Ok((None, None));
    }

    let amount_strings: Vec<String> = amounts.iter().map(|u| u.to_string()).collect();

    // By convention index 0 = BTC, index 1 = TICS (same order used in the old DB mirror).
    let normalize_amount = |s: &String| {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed == "0" {
            None
        } else {
            Some(trimmed.to_string())
        }
    };

    let liquidity_btc = amount_strings.get(0).and_then(normalize_amount);
    let liquidity_tics = amount_strings.get(1).and_then(normalize_amount);

    Ok((liquidity_btc, liquidity_tics))
}

pub(crate) async fn handle_get_solver_liquidity(
    req: SolverLiquidityRequest,
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

    // Fetch liquidity directly from the SolverManager contract
    let (liquidity_btc, liquidity_tics) = match fetch_solver_liquidity_from_contract(&normalized_address).await {
        Ok((btc, tics)) => (btc, tics),
        Err(e) => {
            warn!("❌ Failed to get solver liquidity from contract: {}", e);
            return Ok(warp::reply::json(&SolverLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: None,
                liquidity_tics: None,
                message: "Failed to fetch solver liquidity".to_string(),
                error_message: Some(e),
            }));
        }
    };

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
        "✅ On-chain liquidity for solver {} - BTC: {:?}, TICS: {:?}",
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

/// Return unclaimed rewards for a solver (pending claim-reward requests: Pending, Batched; not Completed).
pub(crate) async fn handle_get_solver_rewards(
    req: GetSolverRewardsRequest,
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🎁 HTTP: get_solver_rewards request for solver: {}",
        req.solver_address
    );

    if req.solver_address.trim().is_empty() {
        return Ok(warp::reply::json(&GetSolverRewardsResponse {
            status: "error".to_string(),
            solver_address: req.solver_address,
            unclaimed_rewards: vec![],
            message: "Solver address is required".to_string(),
            error_message: Some("solver_address cannot be empty".to_string()),
        }));
    }

    let normalized_address = match checksum_from_any(req.solver_address.trim()) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("❌ Invalid solver address format: {}", e);
            return Ok(warp::reply::json(&GetSolverRewardsResponse {
                status: "error".to_string(),
                solver_address: req.solver_address,
                unclaimed_rewards: vec![],
                message: "Invalid solver address format".to_string(),
                error_message: Some(format!("Invalid address format: {e}")),
            }));
        }
    };

    let db = user_intent_manager.get_database();
    let prefix = format!("pending_claim_reward:{}:", normalized_address.to_lowercase());
    let entries: Vec<(String, PendingClaimRewardRequest)> = match db.get_values_with_prefix(&prefix) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                "⚠️ [SOLVER_REWARDS] Failed to load pending claim rewards for solver {}: {}",
                normalized_address, e
            );
            return Ok(warp::reply::json(&GetSolverRewardsResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                unclaimed_rewards: vec![],
                message: "Failed to load pending claim rewards".to_string(),
                error_message: Some(e.to_string()),
            }));
        }
    };

    // Unclaimed = not yet Completed (Pending, Batched, or Failed that can be retried)
    let unclaimed_rewards: Vec<UnclaimedRewardEntry> = entries
        .into_iter()
        .filter(|(_, r)| r.status != "Completed")
        .map(|(_, r)| UnclaimedRewardEntry {
            request_id: r.request_id,
            status: r.status,
            tx_id: r.tx_id,
            ethereum_address: r.ethereum_address,
            btc_address: r.btc_address,
        })
        .collect();

    let count = unclaimed_rewards.len();
    info!(
        "✅ Solver {} has {} unclaimed reward request(s)",
        normalized_address, count
    );

    Ok(warp::reply::json(&GetSolverRewardsResponse {
        status: "success".to_string(),
        solver_address: normalized_address,
        unclaimed_rewards,
        message: format!(
            "{} unclaimed reward request(s) (use claim_reward to submit a new claim)",
            count
        ),
        error_message: None,
    }))
}

pub(crate) async fn handle_claim_reward(
    req: ClaimRewardRequest,
    user_intent_manager: Arc<UserIntentManager>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    if dkg_storage.is_refresh_in_progress().await.unwrap_or(false) {
        warn!("⚠️ HTTP: Blocking claim_reward - shares are getting refreshed");
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            ethereum_address: req.ethereum_address.clone(),
            btc_address: req.btc_address.clone(),
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

    let (compact, v) = match normalize_eth_signature(&req.signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ Invalid signature format: {}", e);
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                reward_btc: None,
                reward_tics: None,
                message: "Invalid signature format".to_string(),
                error_message: Some(format!("Invalid signature: {e:?}")),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
    };

    let solver_address = match recover_eth_address_secp(req.message.as_bytes(), &compact, v, true) {
        Ok(addr) => addr,
        Err(e1) => match recover_eth_address_secp(req.message.as_bytes(), &compact, v, false) {
            Ok(addr) => addr,
            Err(e2) => {
                error!("❌ Failed to recover address: personal_sign={}, raw={}", e1, e2);
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    ethereum_address: req.ethereum_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Failed to recover signature".to_string(),
                    error_message: Some(format!("Failed to recover signature: personal_sign={e1}, raw={e2}")),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        },
    };

    let normalized_address = match checksum_from_any(&solver_address) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("❌ Invalid solver address format: {}", e);
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                reward_btc: None,
                reward_tics: None,
                message: "Invalid solver address format".to_string(),
                error_message: Some(format!("Invalid address format: {e}")),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
    };

    info!("🔐 Recovered solver address from signature: {}", normalized_address);

    // Reject if this solver already has a claim reward request in Pending or Batched (one in-flight per solver).
    {
        let db = user_intent_manager.get_database();
        let prefix = format!("pending_claim_reward:{}:", normalized_address.to_lowercase());
        let entries: Vec<(String, PendingClaimRewardRequest)> = match db.get_values_with_prefix(&prefix) {
            Ok(e) => e,
            Err(e) => {
                warn!("⚠️ [CLAIM_REWARD] Failed to check existing claim requests for solver {}: {}", normalized_address, e);
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    ethereum_address: req.ethereum_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Failed to check existing claim requests".to_string(),
                    error_message: Some("Database error".to_string()),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        };
        let has_pending_or_batched = entries
            .iter()
            .any(|(_, r)| r.status == "Pending" || r.status == "Batched");
        if has_pending_or_batched {
            info!(
                "🚫 [CLAIM_REWARD] Rejecting claim for solver {}: already has a request in Pending/Batched",
                normalized_address
            );
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                reward_btc: None,
                reward_tics: None,
                message: "You already have a claim reward request in progress (Pending or Batched). Wait for it to complete.".to_string(),
                error_message: Some("One claim reward request at a time per solver".to_string()),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
    }

    let request_id = Uuid::new_v4().to_string();
    let pending = PendingClaimRewardRequest {
        request_id: request_id.clone(),
        solver_address: normalized_address.clone(),
        ethereum_address: req.ethereum_address.clone(),
        btc_address: req.btc_address.clone(),
        message: req.message.clone(),
        signature: req.signature.clone(),
        tx_id: None,
        status: "Pending".to_string(),
    };

    let broadcast = ChannelMessage::PendingClaimRewardRequestBroadcast {
        request: pending.clone(),
    };
    if let Err(e) = message_tx.lock().await.send(broadcast).await {
        warn!("⚠️ Failed to broadcast claim_reward request {} to other nodes: {}", request_id, e);
    } else {
        info!("📡 Broadcast claim_reward request {} to other nodes for DB sync", request_id);
    }

    info!(
        "✅ Enqueued claim_reward request {} for solver {}",
        request_id, normalized_address
    );

    Ok(warp::reply::json(&ClaimRewardResponse {
        status: "success".to_string(),
        ethereum_address: req.ethereum_address.clone(),
        btc_address: req.btc_address.clone(),
        reward_btc: None,
        reward_tics: None,
        message: format!(
            "Claim reward request queued for processing (id: {})",
            request_id
        ),
        error_message: None,
        tics_reward_tx_id: None,
        btc_reward_tx_id: None,
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

    // All solver and liquidity checks below use the SolverManager contract only (no DB).
    // Contract config: SOLVER_CONTRACT_ADDRESS, SOLVER_CONTRACT_RPC_URL, SOLVER_CONTRACT_CHAIN_ID.
    // Liquidity and minimums are fetched via get_solver_id, get_all_chain_amounts, get_minimum_liquidity_*.
    let (liquidity_btc_str, liquidity_tics_str) =
        match fetch_solver_liquidity_from_contract(&normalized_address).await {
            Ok((btc, tics)) => (btc, tics),
            Err(e) => {
                warn!("❌ Failed to get solver liquidity from contract: {}", e);
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
                    error_message: Some(e),
                }));
            }
        };

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

    // Fetch minimum liquidity thresholds from the same SolverManager contract (no DB)
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

    // At this point all validations have passed and we know:
    // - which asset (TICS or BTC) is being withdrawn
    // - the normalized solver address
    // - the validated destination address
    //
    // Reject if this solver already has a withdraw request in Pending or Batched status
    // (one in-flight withdraw per solver at a time; persists over gossip so no duplicate on any node).
    {
        let db = user_intent_manager.get_database();
        let prefix = format!(
            "pending_withdraw_liquidity:{}:",
            normalized_address.to_lowercase()
        );
        let entries: Vec<(String, PendingWithdrawRequest)> = match db.get_values_with_prefix(&prefix) {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    "⚠️ [WITHDRAW_LIQUIDITY] Failed to check existing withdraw requests for solver {}: {}",
                    normalized_address, e
                );
                return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                    status: "error".to_string(),
                    solver_address: normalized_address.clone(),
                    liquidity_btc: liquidity_btc_str.clone(),
                    liquidity_tics: liquidity_tics_str.clone(),
                    ethereum_address: req.ethereum_address.clone(),
                    btc_address: req.btc_address.clone(),
                    tics_withdraw_tx_id: None,
                    btc_withdraw_tx_id: None,
                    message: "Failed to check existing withdraw requests".to_string(),
                    error_message: Some("Database error".to_string()),
                }));
            }
        };
        let has_pending_or_batched = entries
            .iter()
            .any(|(_, r)| r.status == "Pending" || r.status == "Batched");
        if has_pending_or_batched {
            info!(
                "🚫 [WITHDRAW_LIQUIDITY] Rejecting withdraw for solver {}: already has a request in Pending/Batched",
                normalized_address
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                liquidity_btc: liquidity_btc_str.clone(),
                liquidity_tics: liquidity_tics_str.clone(),
                ethereum_address: req.ethereum_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "You already have a withdraw request in progress (Pending or Batched). Wait for it to complete.".to_string(),
                error_message: Some("One withdraw request at a time per solver".to_string()),
            }));
        }
    }

    // Instead of initiating on-chain withdrawals immediately, we now enqueue a
    // pending withdraw request in the database to be processed later in batch.

    // Determine which asset and amount are being withdrawn
    let (asset, amount) = if let Some(amount) = &withdraw_tics_amount {
        ("TICS".to_string(), amount.clone())
    } else if let Some(amount) = &withdraw_btc_amount {
        ("BTC".to_string(), amount.clone())
    } else {
        let msg = "No withdrawal amount provided after validation".to_string();
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
    };

    let request_id = Uuid::new_v4().to_string();
    let pending = crate::types::rpc_server::PendingWithdrawRequest {
        request_id: request_id.clone(),
        solver_address: normalized_address.clone(),
        asset: asset.clone(),
        amount: amount.clone(),
        ethereum_address: req.ethereum_address.clone(),
        btc_address: req.btc_address.clone(),
        message: req.message.clone(),
        tx_id: None,
        status: "Pending".to_string(),
    };

    // Broadcast via channel; storage happens only in gossip handler (for this node and all others).
    let broadcast = ChannelMessage::PendingWithdrawRequestBroadcast {
        request: pending.clone(),
    };
    if let Err(e) = message_tx.lock().await.send(broadcast).await {
        warn!(
            "⚠️ Failed to broadcast withdraw_liquidity request {} to other nodes: {}",
            request_id, e
        );
    } else {
        info!(
            "📡 Broadcast withdraw_liquidity request {} to other nodes for DB sync",
            request_id
        );
    }

    info!(
        "✅ Enqueued withdraw_liquidity request {} for solver {} (asset={}, amount={})",
        request_id, normalized_address, asset, amount
    );

    // No on-chain transaction has been sent yet; we only acknowledge queuing.
    Ok(warp::reply::json(&WithdrawLiquidityResponse {
        status: "success".to_string(),
        solver_address: normalized_address,
        liquidity_btc: liquidity_btc_str,
        liquidity_tics: liquidity_tics_str,
        ethereum_address: req.ethereum_address.clone(),
        btc_address: req.btc_address.clone(),
        tics_withdraw_tx_id: None,
        btc_withdraw_tx_id: None,
        message: format!(
            "Withdraw request queued for batch processing (id: {}, asset: {}, amount: {})",
            request_id, asset, amount
        ),
        error_message: None,
    }))
}

/// Handle solver_add_liquidity RPC.
///
/// This endpoint:
/// - Verifies that the signed payload was signed by VERIFICATION_ADDRESS.
/// - Parses the payload fields (solverId, solverAddress, amount, chainId).
/// - Pushes a ChannelMessage::SolverAddLiquidity into the internal channel.
/// - Does NOT persist anything to DB and does NOT track status.
pub(crate) async fn handle_add_liquidity(
    req: AddLiquidityRequest,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    use crate::rpc_server::utils::{normalize_eth_signature, recover_eth_address_secp};

    info!("💧 HTTP: add_liquidity request with message: {}", req.message);

    // 1) Load VERIFICATION_ADDRESS from env (must NOT be hardcoded).
    let verification_address_raw =
        std::env::var("VERIFICATION_ADDRESS").unwrap_or_else(|_| "".to_string());
    if verification_address_raw.trim().is_empty() {
        warn!("❌ [ADD_LIQUIDITY] VERIFICATION_ADDRESS not configured");
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            message: "VERIFICATION_ADDRESS not configured".to_string(),
            error_message: Some("VERIFICATION_ADDRESS env var is missing".to_string()),
        }));
    }

    // 2) Recover signer from signature over the raw `message` bytes.
    let (compact, v) = match normalize_eth_signature(&req.signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ [ADD_LIQUIDITY] Invalid signature format: {}", e);
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                message: "Invalid signature format".to_string(),
                error_message: Some(format!("Invalid signature: {e:?}")),
            }));
        }
    };

    let msg_bytes = req.message.as_bytes();
    let recovered_address = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
        Ok(addr) => addr,
        Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
            Ok(addr) => addr,
            Err(e2) => {
                error!(
                    "❌ [ADD_LIQUIDITY] Failed to recover verification address: personal_sign={}, raw={}",
                    e1, e2
                );
                return Ok(warp::reply::json(&AddLiquidityResponse {
                    status: "error".to_string(),
                    message: "Failed to recover signature".to_string(),
                    error_message: Some(format!(
                        "Failed to recover signature: personal_sign={e1}, raw={e2}"
                    )),
                }));
            }
        },
    };

    // Normalize both recovered and env addresses for comparison.
    let recovered_lower = recovered_address.to_lowercase();
    let verification_lower = verification_address_raw.to_lowercase();

    if recovered_lower != verification_lower {
        warn!(
            "❌ [ADD_LIQUIDITY] Verification failed: recovered_signer={}, expected={}",
            recovered_address, verification_address_raw
        );
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            message: "Unauthorized add_liquidity request".to_string(),
            error_message: Some("Recovered signer does not match VERIFICATION_ADDRESS".to_string()),
        }));
    }

    // 3) Parse signed payload.
    // NOTE: request_id is NOT supplied by the external user; it is generated
    // internally by this node (see below) and then propagated via messaging.
    #[derive(serde::Deserialize)]
    struct AddLiquidityPayload {
        #[serde(rename = "solverId")]
        solver_id: String,
        #[serde(rename = "solverAddress")]
        solver_address: String,
        amount: String,
        #[serde(rename = "chainId")]
        chain_id: u64,
    }

    let payload: AddLiquidityPayload = match serde_json::from_str(&req.message) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                "❌ [ADD_LIQUIDITY] Failed to parse signed payload JSON: {}",
                e
            );
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                message: "Invalid signed payload format".to_string(),
                error_message: Some(format!("Failed to parse payload JSON: {e}")),
            }));
        }
    };

    if payload.amount.trim().is_empty() || payload.amount == "0" {
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            message: "Amount must be greater than zero".to_string(),
            error_message: Some("amount must be non-zero".to_string()),
        }));
    }

    // Basic chainId validation (0 = BTC, 9029 = EVM / Qubetics).
    if payload.chain_id != 0 && payload.chain_id != 9029 {
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            message: "Unsupported chainId".to_string(),
            error_message: Some("chainId must be 0 (BTC) or 9029 (EVM)".to_string()),
        }));
    }

    info!(
        "✅ [ADD_LIQUIDITY] Verified request for solver_id={} solver_address={} amount={} chain_id={}",
        payload.solver_id, payload.solver_address, payload.amount, payload.chain_id
    );

    // 4) Enqueue as ChannelMessage so the network layer can gossip + batch later.
    let timestamp_ms = chrono::Utc::now().timestamp_millis();

    // Generate an internal request_id that is *not* user-controlled.
    // This is deterministic for this node and then propagated via ChannelMessage/gossip.
    let request_id = format!(
        "addliq:{}:{}:{}:{}",
        payload.solver_id,
        payload.solver_address.to_lowercase(),
        payload.chain_id,
        timestamp_ms
    );

    {
        let tx = message_tx.lock().await;
        if let Err(e) = tx
            .send(ChannelMessage::SolverAddLiquidity {
                request_id: request_id.clone(),
                solver_id: payload.solver_id.clone(),
                solver_address: payload.solver_address.clone(),
                amount: payload.amount.clone(),
                chain_id: payload.chain_id,
                signature: req.signature.clone(),
                signed_payload: req.message.clone(),
                timestamp_ms,
                status: "Pending".to_string(),
            })
            .await
        {
            error!(
                "❌ [ADD_LIQUIDITY] Failed to enqueue SolverAddLiquidity message: {}",
                e
            );
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                message: "Failed to enqueue add_liquidity request".to_string(),
                error_message: Some(format!("Channel error: {e}")),
            }));
        }
    }

    Ok(warp::reply::json(&AddLiquidityResponse {
        status: "success".to_string(),
        message: "add_liquidity request accepted.".to_string(),
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
    let network_share_pubkey = match dkg_storage.get_network_share_pubkey(&request.peer_id).await {
        Ok(Some(pubkey)) => {
            let pubkey_bytes = pubkey.to_affine().to_encoded_point(true);
            Some(hex::encode(pubkey_bytes.as_bytes()))
        }
        Ok(None) => {
            warn!(
                "⚠️ [RPC] Network share pubkey not found for peer: {}",
                request.peer_id
            );
            None
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get network share pubkey: {}", e);
            None
        }
    };

    // Get liquidity operator (vault) share pubkey
    let vault_share_pubkey = match dkg_storage.get_vault_share_pubkey(&request.peer_id).await {
        Ok(Some(pubkey)) => {
            let pubkey_bytes = pubkey.to_affine().to_encoded_point(true);
            Some(hex::encode(pubkey_bytes.as_bytes()))
        }
        Ok(None) => {
            warn!(
                "⚠️ [RPC] Liquidity operator share pubkey not found for peer: {}",
                request.peer_id
            );
            None
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get liquidity operator share pubkey: {}", e);
            None
        }
    };

    // Get all user share pubkeys
    let user_share_pubkeys = match dkg_storage
        .get_all_user_share_pubkeys_for_peer(&request.peer_id)
        .await
    {
        Ok(user_pubkeys) => user_pubkeys
            .into_iter()
            .map(|(user_addr, pubkey)| {
                let pubkey_bytes = pubkey.to_affine().to_encoded_point(true);
                crate::types::rpc_server::UserSharePubkeyInfo {
                    user_eth_address: user_addr,
                    share_pubkey: hex::encode(pubkey_bytes.as_bytes()),
                }
            })
            .collect(),
        Err(e) => {
            error!("❌ [RPC] Failed to get user share pubkeys: {}", e);
            Vec::new()
        }
    };

    // Log all the information
    info!(
        "🔑 [RPC] === Partial Pubkeys for Peer: {} ===",
        request.peer_id
    );
    if let Some(ref network_pubkey) = network_share_pubkey {
        info!("  📍 Network Share Pubkey: 0x{}", network_pubkey);
    }
    if let Some(ref vault_pubkey) = vault_share_pubkey {
        info!("  📍 Liquidity operator share pubkey: 0x{}", vault_pubkey);
    }
    info!(
        "  📍 User Share Pubkeys ({} users):",
        user_share_pubkeys.len()
    );
    for user_info in &user_share_pubkeys {
        info!(
            "     User: {} -> Pubkey: 0x{}",
            user_info.user_eth_address, user_info.share_pubkey
        );
    }
    info!("✅ [RPC] === Finished logging partial pubkeys ===");

    let peer_id = request.peer_id.clone();
    let user_count = user_share_pubkeys.len();
    Ok(warp::reply::json(
        &crate::types::rpc_server::LogPartialPubkeysResponse {
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
        },
    ))
}

/// Get network and liquidity operator addresses (TICS/ETH and BTC)
/// These addresses are the same across all nodes in the network
/// Uses aggregated group keys, not individual share pubkeys
pub(crate) async fn handle_get_network_addresses(
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📍 [RPC] Getting network addresses (same across all nodes)");

    // Get final aggregated public key (network/main group key)
    let network_addresses = match dkg_storage.get_final_public().await {
        Ok(Some(final_public)) => {
            let eth_addr = crate::utils::get_eth_address_from_group_key(final_public);
            let btc_addr = crate::utils::get_btc_address_from_group_key(final_public);
            Some(crate::types::rpc_server::AddressInfo {
                eth_address: eth_addr,
                btc_address: btc_addr,
            })
        }
        Ok(None) => {
            warn!("⚠️ [RPC] Final public key (network group key) not found");
            None
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get final public key: {}", e);
            None
        }
    };

    // Get liquidity operator aggregated group key
    let liquidity_operator_addresses = match dkg_storage.get_vault_group_key().await {
        Ok(Some(liquidity_operator_group_key)) => {
            let eth_addr = crate::utils::get_eth_address_from_group_key(liquidity_operator_group_key);
            let btc_addr = crate::utils::get_btc_address_from_group_key(liquidity_operator_group_key);
            Some(crate::types::rpc_server::AddressInfo {
                eth_address: eth_addr,
                btc_address: btc_addr,
            })
        }
        Ok(None) => {
            warn!("⚠️ [RPC] Liquidity operator group key not found");
            None
        }
        Err(e) => {
            error!("❌ [RPC] Failed to get liquidity operator group key: {}", e);
            None
        }
    };

    // Log the addresses
    if let Some(ref net_addrs) = network_addresses {
        info!(
            "📍 [RPC] Network Addresses: ETH={}, BTC={}",
            net_addrs.eth_address, net_addrs.btc_address
        );
    }
    if let Some(ref liquidity_operator_addrs) = liquidity_operator_addresses {
        info!(
            "📍 [RPC] Liquidity Operator Addresses: ETH={}, BTC={}",
            liquidity_operator_addrs.eth_address, liquidity_operator_addrs.btc_address
        );
    }

    Ok(warp::reply::json(
        &crate::types::rpc_server::GetNetworkAddressesResponse {
            status: "success".to_string(),
            network_addresses,
            liquidity_operator_addresses,
            message: "Retrieved network addresses (same across all nodes)".to_string(),
            error_message: None,
        },
    ))
}
