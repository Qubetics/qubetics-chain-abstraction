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
    contract::{fetch_dynamic_fee_bps, ContractClient, ContractConfig, SolverManagerContract},
    database::{Database, DkgStorage},
    types::{
        intent::{DepositIntent, DepositIntentResponse, TransactionType},
        messaging::ChannelMessage,
        rpc_server::{
            AddLiquidityRequest, AddLiquidityResponse, ClaimPlatformFeeRequest,
            ClaimPlatformFeeResponse, ClaimRewardRequest, ClaimRewardResponse, DKGStatusResponse,
            EnhancedUserRegistrationResponse, GetSolverRewardsRequest, GetSolverRewardsResponse,
            HeartbeatResponse, IntentDetailsResponse, IntentsSolvedCountResponse, NodeIdResponse,
            PeerConnectionResponse, PendingClaimPlatformFeeRequest, PendingClaimRewardRequest,
            PendingIntentsCountResponse, PendingWithdrawRequest, RejoinStatusResponse,
            RequestContext, SolverLiquidityRequest, SolverLiquidityResponse, UnclaimedRewardEntry,
            UptimeResponse, UserCountResponse, UserInfoResponse, UserMpcDepositRequest,
            UserMpcDepositVerifyResponse, UserRegistrationRequest, WithdrawLiquidityRequest,
            WithdrawLiquidityResponse,
        },
        IntentStatus,
    },
    user_intent_manager::{checksum_from_any, UserIntentManager},
};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use crate::utils::transaction::DUST_LIMIT_SATS;

use super::{
    errors::{RpcError, TransactionError},
    utils::{normalize_eth_signature, recover_eth_address_secp},
};

/// Minimum TICS unclaimed to allow a claim (1 TICS = 10^18 wei).
const MIN_CLAIM_TICS_WEI: u64 = 1_000_000_000_000_000_000;

pub(crate) async fn handle_deposit_intent(
    intent: DepositIntent,
    user_tics_address: Option<String>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    transaction_type: TransactionType,
    _dkg_storage: Arc<DkgStorage>,
    signature: Option<String>,
    target_amount: u128,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📝 HTTP: Received deposit intent request");
    if let Some(addr) = &user_tics_address {
        info!("📝 HTTP: User TICS address provided for signing: {}", addr);
    }

    // Parse string amount into u128 for internal processing
    // (validation already done at RPC level in handle_user_mpc_deposit)
    let parsed_amount = intent.amount.parse::<u128>().map_err(|_| {
        warp::reject::custom(RpcError::InvalidRequest(format!(
            "Invalid deposit amount: {}",
            intent.amount
        )))
    })?;

    let fee_bps = fetch_dynamic_fee_bps().await;
    let required_amount_u128 = parsed_amount + (parsed_amount * fee_bps / 10000);

    let intent_id = format!("intent-{}", Uuid::new_v4());
    let deposit_intent_msg = ChannelMessage::DepositIntent {
        intent: intent.clone(),
        intent_id: intent_id.clone(),
        user_tics_address: user_tics_address
            .as_ref()
            .map(|s| s.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        transaction_type: transaction_type.clone(),
        amount: required_amount_u128,
        target_amount,
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
        tics_address: req.tics_address.clone(),
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
        request.tics_address
    );

    // Input validation
    let addr_cs = match super::errors::validate_tics_address(&request.tics_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!(
                "❌ HTTP: Address validation failed for '{}': {:?}",
                request.tics_address, e
            );
            let error_response = EnhancedUserRegistrationResponse {
                status: "error".to_string(),
                message: "Invalid TICS address".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(e.to_error_response()),
            };
            return Ok(warp::reply::json(&error_response));
        }
    };

    // Signature verification - verify that the user controls the TICS address
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
                        "Signature and message are required for user registration to prove ownership of the TICS address".to_string()
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

    // Verify that recovered address matches the provided tics_address
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
    // Expected format: "register:{tics_address}:{timestamp}"
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
                tics_address: addr_cs.clone(),
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
                        "Derived addresses (TICS/BTC) were not generated within {} seconds. Please try again later.",
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
                    "📬 HTTP: Derived TICS address stored for {} -> {}",
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

pub(crate) async fn handle_register_admin(
    request: crate::types::rpc_server::AdminRegistrationRequest,
    user_intent_manager: Arc<UserIntentManager>,
    dkg_storage: Arc<DkgStorage>,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    node_id: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    use crate::types::rpc_server::AdminRegistrationResponse;

    info!(
        "👤 HTTP: Received admin registration request for address: {}",
        request.tics_address
    );

    // --- 1. Validate TICS address ---
    let addr_cs = match super::errors::validate_tics_address(&request.tics_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!(
                "❌ HTTP: Address validation failed for '{}': {:?}",
                request.tics_address, e
            );
            return Ok(warp::reply::json(&AdminRegistrationResponse {
                status: "error".to_string(),
                message: "Invalid TICS address".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(e.to_error_response()),
            }));
        }
    };

    // --- 2. Load ADMIN_PUBLIC_ADDRESS from env (or default) ---
    let admin_public_address = crate::env_defaults::admin_public_address()
        .trim()
        .to_string();
    if admin_public_address.is_empty() {
        error!("❌ ADMIN_PUBLIC_ADDRESS env var is not configured");
        return Ok(warp::reply::json(&AdminRegistrationResponse {
            status: "error".to_string(),
            message: "ADMIN_PUBLIC_ADDRESS not configured on this node".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest(
                    "ADMIN_PUBLIC_ADDRESS env var is not configured".to_string(),
                )
                .to_error_response(),
            ),
        }));
    }

    // --- 3. Normalize and verify signature ---
    let (compact, v) = match normalize_eth_signature(&request.signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ Failed to normalize admin signature: {}", e);
            return Ok(warp::reply::json(&AdminRegistrationResponse {
                status: "error".to_string(),
                message: "Invalid signature format".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(
                    RpcError::InvalidRequest(format!("Invalid signature format: {e}"))
                        .to_error_response(),
                ),
            }));
        }
    };

    let msg_bytes = request.message.as_bytes();
    let recovered_address = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
        Ok(addr) => addr,
        Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
            Ok(addr) => addr,
            Err(e2) => {
                error!(
                    "❌ Both signature recovery methods failed for admin registration: personal_sign={}, raw={}",
                    e1, e2
                );
                return Ok(warp::reply::json(&AdminRegistrationResponse {
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
                }));
            }
        },
    };

    // --- 4. Verify recovered address matches ADMIN_PUBLIC_ADDRESS from env ---
    if recovered_address.to_lowercase() != admin_public_address.to_lowercase() {
        error!(
            "❌ Admin signature verification failed: recovered={}, expected ADMIN_PUBLIC_ADDRESS={}",
            recovered_address, admin_public_address
        );
        return Ok(warp::reply::json(&AdminRegistrationResponse {
            status: "error".to_string(),
            message: "Unauthorized: signer does not match ADMIN_PUBLIC_ADDRESS".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest(
                    "Recovered signer does not match ADMIN_PUBLIC_ADDRESS".to_string(),
                )
                .to_error_response(),
            ),
        }));
    }

    // --- 5. Validate message format and timestamp ---
    // Expected format: "register_admin:{tics_address}:{timestamp}"
    let parts: Vec<&str> = request.message.split(':').collect();
    if parts.len() != 3 || parts[0] != "register_admin" {
        warn!("⚠️ Invalid message format, expected: register_admin:{{address}}:{{timestamp}}");
        return Ok(warp::reply::json(&AdminRegistrationResponse {
            status: "error".to_string(),
            message: "Invalid message format".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest(
                    "Invalid message format. Expected: register_admin:{address}:{timestamp}"
                        .to_string(),
                )
                .to_error_response(),
            ),
        }));
    }

    // Verify the address in the message matches the provided tics_address
    let message_addr = match checksum_from_any(parts[1]) {
        Ok(addr) => addr,
        Err(e) => {
            error!("❌ Invalid address in message: {}", e);
            return Ok(warp::reply::json(&AdminRegistrationResponse {
                status: "error".to_string(),
                message: "Invalid address in message".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(
                    RpcError::InvalidRequest(format!("Invalid address in message: {e}"))
                        .to_error_response(),
                ),
            }));
        }
    };

    if message_addr.to_lowercase() != addr_cs.to_lowercase() {
        error!(
            "❌ Address in message {} does not match provided address {}",
            message_addr, addr_cs
        );
        return Ok(warp::reply::json(&AdminRegistrationResponse {
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
        }));
    }

    // Validate timestamp (5-minute window)
    if let Ok(timestamp) = parts[2].parse::<i64>() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let time_diff = (now - timestamp).abs();
        const MAX_TIME_DIFF: i64 = 300;

        if time_diff > MAX_TIME_DIFF {
            warn!(
                "⚠️ Timestamp validation failed: time difference {} seconds exceeds maximum {} seconds",
                time_diff, MAX_TIME_DIFF
            );
            return Ok(warp::reply::json(&AdminRegistrationResponse {
                status: "error".to_string(),
                message: "Timestamp validation failed: message expired or invalid".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(
                    RpcError::InvalidRequest(format!(
                        "Timestamp validation failed: time difference {} seconds exceeds maximum {} seconds",
                        time_diff, MAX_TIME_DIFF
                    ))
                    .to_error_response(),
                ),
            }));
        }
    } else {
        warn!("⚠️ Invalid timestamp format in message");
        return Ok(warp::reply::json(&AdminRegistrationResponse {
            status: "error".to_string(),
            message: "Invalid timestamp format in message".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest("Invalid timestamp format in message".to_string())
                    .to_error_response(),
            ),
        }));
    }

    info!(
        "✅ Admin signature verification successful for address: {}",
        addr_cs
    );

    // --- 6. Check if admin is already registered (under "admin:" prefix) ---
    if let Some(_existing_admin) = user_intent_manager.get_admin_by_address(&addr_cs).await {
        info!("⚠️ HTTP: Admin already registered: {}", addr_cs);
        return Ok(warp::reply::json(&AdminRegistrationResponse {
            status: "error".to_string(),
            message: "Admin is already registered".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::InvalidRequest("Admin is already registered".to_string())
                    .to_error_response(),
            ),
        }));
    }

    // --- 7. Check DKG status ---
    let dkg_secret_share = get_actual_dkg_secret_share(dkg_storage).await;
    if dkg_secret_share.is_none() {
        warn!("⚠️ HTTP: DKG not ready for admin registration");
        return Ok(warp::reply::json(&AdminRegistrationResponse {
            status: "error".to_string(),
            message: "DKG system is not ready. Please try again later.".to_string(),
            derived_eth_address: None,
            derived_btc_address: None,
            error: Some(
                RpcError::DkgNotReady("DKG secret share not available".to_string())
                    .to_error_response(),
            ),
        }));
    }

    // --- 8. Register admin (stored separately under "admin:" prefix) ---
    match user_intent_manager
        .register_admin(&addr_cs, dkg_secret_share.as_ref(), &node_id)
        .await
    {
        Ok(registration) => {
            info!(
                "✅ HTTP: Admin registration successful for address: {}",
                addr_cs
            );

            // Broadcast to peers via dedicated AdminRegistration channel message
            let admin_reg_msg = ChannelMessage::AdminRegistration {
                tics_address: addr_cs.clone(),
                node_id: node_id.to_string(),
            };

            if let Ok(tx) = message_tx.try_lock() {
                if let Err(e) = tx.send(admin_reg_msg).await {
                    error!(
                        "❌ Failed to send admin registration message to network: {}",
                        e
                    );
                    warn!("⚠️ Admin registered locally but network broadcast failed");
                } else {
                    info!("📡 Admin registration message sent to network layer for broadcasting");
                }
            } else {
                warn!("⚠️ Could not acquire message channel lock for network broadcast");
            }

            // Wait for derived addresses
            info!("⏳ Waiting for admin derived addresses to be populated...");
            let mut attempts = 0;
            const MAX_ATTEMPTS: u8 = 10;

            let mut derived_eth = registration.derived_eth_address.clone();
            let mut derived_btc = registration.derived_btc_address.clone();
            while attempts < MAX_ATTEMPTS {
                match user_intent_manager.get_admin_by_address(&addr_cs).await {
                    Some(updated_admin) => {
                        if updated_admin.derived_eth_address.is_some()
                            && updated_admin.derived_btc_address.is_some()
                        {
                            derived_eth = updated_admin.derived_eth_address;
                            derived_btc = updated_admin.derived_btc_address;
                            info!("✅ Admin derived addresses are now available!");
                            break;
                        }
                    }
                    None => {
                        warn!("⚠️ Admin temporarily missing from registry during address derivation, retrying...");
                    }
                }

                attempts += 1;
                if attempts < MAX_ATTEMPTS {
                    info!(
                        "⏳ Attempt {}/{}: Admin derived addresses not ready yet, waiting 1 second...",
                        attempts, MAX_ATTEMPTS
                    );
                    sleep(Duration::from_secs(1)).await;
                }
            }

            if derived_eth.is_none() || derived_btc.is_none() {
                error!(
                    "❌ HTTP: Admin derived addresses not available after {} attempts",
                    MAX_ATTEMPTS
                );
                return Ok(warp::reply::json(&AdminRegistrationResponse {
                    status: "error".to_string(),
                    message: format!(
                        "Derived addresses (TICS/BTC) were not generated within {} seconds. Please try again later.",
                        MAX_ATTEMPTS
                    ),
                    derived_eth_address: derived_eth,
                    derived_btc_address: derived_btc,
                    error: Some(
                        RpcError::Timeout(format!(
                            "Derived addresses not generated within {} seconds",
                            MAX_ATTEMPTS
                        ))
                        .to_error_response(),
                    ),
                }));
            }

            if let Some(eth_addr) = &derived_eth {
                info!(
                    "📬 HTTP: Admin derived TICS address stored for {} -> {}",
                    addr_cs, eth_addr
                );
            }
            if let Some(btc_addr) = &derived_btc {
                info!(
                    "📬 HTTP: Admin derived BTC address stored for {} -> {}",
                    addr_cs, btc_addr
                );
            }

            Ok(warp::reply::json(&AdminRegistrationResponse {
                status: "success".to_string(),
                message: "Admin registered successfully".to_string(),
                derived_eth_address: derived_eth,
                derived_btc_address: derived_btc,
                error: None,
            }))
        }
        Err(e) => {
            error!(
                "❌ HTTP: Admin registration failed for address {}: {}",
                addr_cs, e
            );

            Ok(warp::reply::json(&AdminRegistrationResponse {
                status: "error".to_string(),
                message: "Admin registration failed".to_string(),
                derived_eth_address: None,
                derived_btc_address: None,
                error: Some(RpcError::RegistrationFailed(e.to_string()).to_error_response()),
            }))
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
                intent_hash: "".to_string(),
                error_message: Some("Invalid deposit intent payload".to_string()),
                signer_eth_address: None,
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
    if user_intent_manager
        .get_intent(&intent_hash_hex)
        .await
        .is_some()
    {
        warn!(
            request_id = %request_context.request_id,
            intent_hash = %intent_hash_hex,
            "⚠️ HTTP: Rejecting deposit - intent hash already exists (duplicate); no processing"
        );
        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            intent_hash: intent_hash_hex.clone(),
            error_message: Some(
                "Intent hash already exists - this deposit has already been processed".to_string(),
            ),
            signer_eth_address: None,
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
                signer_eth_address: None,
            }));
        }
    };

    // Recover signer and reject immediately if user is not registered (no further processing).
    let (compact, v) = match normalize_eth_signature(signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ Failed to normalize signature: {}", e);
            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                status: "error".to_string(),
                intent_hash: intent_hash_hex.clone(),
                error_message: Some(format!("Invalid signature format: {e}")),
                signer_eth_address: None,
            }));
        }
    };
    let (signer, _used_personal) = match recover_eth_address_secp(intent_bytes, &compact, v, true) {
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
                        signer_eth_address: None,
                    }));
                }
            }
        }
    };
    let signer_user = match user_intent_manager.get_user_by_address(&signer).await {
        Some(u) => u,
        None => {
            warn!(
                request_id = %request_context.request_id,
                intent_hash = %intent_hash_hex,
                signer = %signer,
                "⚠️ HTTP: Rejecting deposit - signer not registered"
            );
            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                status: "error".to_string(),
                intent_hash: intent_hash_hex.clone(),
                error_message: Some(
                    "User not registered. Please register first (register_user) before submitting a deposit.".to_string(),
                ),
                signer_eth_address: Some(signer.clone()),
            }));
        }
    };

    // Only support UserToVault transaction type
    let transaction_type = TransactionType::UserToVault;

    // CRITICAL: Validate intent BEFORE storing intent_hash to prevent orphaned hashes
    if let Err(e) =
        crate::utils::intent_validation::validate_intent_chains_tokens_addresses(&req.msg)
    {
        warn!(
            request_id = %request_context.request_id,
            intent_hash = %intent_hash_hex,
            "⚠️ HTTP: Rejecting deposit - chain/token/address validation failed: {}",
            e
        );
        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
            status: "error".to_string(),
            intent_hash: intent_hash_hex.clone(),
            error_message: Some(format!("Invalid intent: {}", e)),
            signer_eth_address: None,
        }));
    }

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

    let (user_registration, computed_target_amount) = match user_intent_manager
        .get_user_by_intent_hash(&intent_hash_hex)
        .await
    {
        Some(existing_user) => (existing_user, 0u128), // existing intent won't be re-processed
        None => {
            {
                info!("No existing user found for intent hash, using signer registration.");
                let user_reg = signer_user;

                // CRITICAL: Check if user has sufficient balance on source chain BEFORE storing intent
                info!(
                    "💰 [HTTP] Checking source address balance for intent: {} (amount: {})",
                    intent_hash_hex, req.msg.amount
                );

                let source_amount = match req.msg.amount.parse::<u128>() {
                    Ok(amt) => amt,
                    Err(e) => {
                        warn!("❌ Invalid amount format in intent: {}", e);
                        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                            status: "error".to_string(),
                            intent_hash: intent_hash_hex.clone(),
                            error_message: Some(format!("Invalid amount format: {}", e)),
                            signer_eth_address: None,
                        }));
                    }
                };

                // Reject zero-amount intents immediately
                if source_amount == 0 {
                    warn!(
                        "⚠️ [HTTP] Rejecting intent {} - amount is zero",
                        intent_hash_hex
                    );
                    return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                        status: "error".to_string(),
                        intent_hash: intent_hash_hex.clone(),
                        error_message: Some("Amount must be greater than zero".to_string()),
                        signer_eth_address: None,
                    }));
                }

                // Determine blockchain for balance check
                let source_blockchain = if req.msg.source_chain.eq_ignore_ascii_case("btc")
                    || req.msg.source_chain.eq_ignore_ascii_case("bitcoin")
                {
                    "btc"
                } else {
                    "eth"
                };

                // Calculate required balance: amount + dynamic buffer + estimated tx fee
                let fee_bps = fetch_dynamic_fee_bps().await;
                let dynamic_fee_buffer = (source_amount * fee_bps) / 10000;
                let estimated_tx_fee: u128 = if source_blockchain == "btc" {
                    // BTC: conservative estimate for P2WPKH tx (2 inputs, 2 outputs)
                    // vbytes = 10 + 68*2 + 31*2 = 208, fee = 208 * 2 sat/vbyte = 416 sats
                    let fee_rate = std::env::var("BTC_FEE_RATE_SAT_VB")
                        .ok()
                        .and_then(|v| v.parse::<u128>().ok())
                        .unwrap_or(2);
                    208 * fee_rate
                } else {
                    // TICS (EVM): gas_limit=300_000, gas_price=1 Gwei (1e9 wei)
                    // fee = 300_000 * 1_000_000_000 = 300_000_000_000_000 wei (0.0003 TICS)
                    300_000_000_000_000u128
                };
                let required_balance = source_amount + dynamic_fee_buffer + estimated_tx_fee;

                // Fetch user's source address balance
                match crate::rpc_server::utils::fetch_network_balance(
                    &req.msg.source_address,
                    source_blockchain,
                )
                .await
                {
                    Ok(user_balance) => {
                        if user_balance < required_balance {
                            warn!(
                                "⚠️ [HTTP] Insufficient balance for intent {}: user has {}, needs {} (amount {} + dynamic fee buffer {} + est. fee {})",
                                intent_hash_hex, user_balance, required_balance,
                                source_amount, dynamic_fee_buffer, estimated_tx_fee
                            );
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                intent_hash: intent_hash_hex.clone(),
                                error_message: Some(format!(
                                    "Insufficient balance: you have {} but need {} (amount {} + dynamic fee buffer {} + estimated fee {})",
                                    user_balance, required_balance,
                                    source_amount, dynamic_fee_buffer, estimated_tx_fee
                                )),
                                signer_eth_address: None,
                            }));
                        } else {
                            info!(
                                "✅ [HTTP] Source address has sufficient balance: {} >= {} (amount {} + dynamic fee {} + fee {})",
                                user_balance, required_balance, source_amount, dynamic_fee_buffer, estimated_tx_fee
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "⚠️ [HTTP] Failed to fetch source address balance for {}: {}",
                            intent_hash_hex, e
                        );
                        return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                            status: "error".to_string(),
                            intent_hash: intent_hash_hex.clone(),
                            error_message: Some(format!(
                                "Failed to verify source address balance: {}",
                                e
                            )),
                            signer_eth_address: None,
                        }));
                    }
                }

                // Validate target address is reachable (balance fetch succeeds)
                let target_blockchain = if req.msg.target_chain.eq_ignore_ascii_case("btc")
                    || req.msg.target_chain.eq_ignore_ascii_case("bitcoin")
                {
                    "btc"
                } else {
                    "eth"
                };
                if let Err(e) = crate::rpc_server::utils::fetch_network_balance(
                    &req.msg.target_address,
                    target_blockchain,
                )
                .await
                {
                    warn!(
                        "⚠️ [HTTP] Target address validation failed for intent {}: {}",
                        intent_hash_hex, e
                    );
                    return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                        status: "error".to_string(),
                        intent_hash: intent_hash_hex.clone(),
                        error_message: Some(format!(
                            "Invalid or unreachable target address {}: {}",
                            req.msg.target_address, e
                        )),
                        signer_eth_address: None,
                    }));
                }

                // Compute target amount for all directions (same-chain and cross-chain)
                let src_is_tics = req.msg.source_chain.eq_ignore_ascii_case("tics")
                    || req.msg.source_chain.eq_ignore_ascii_case("qubetics")
                    || req.msg.source_chain.eq_ignore_ascii_case("evm");
                let dst_is_tics = req.msg.target_chain.eq_ignore_ascii_case("tics")
                    || req.msg.target_chain.eq_ignore_ascii_case("qubetics")
                    || req.msg.target_chain.eq_ignore_ascii_case("evm");
                let src_is_btc = req.msg.source_chain.eq_ignore_ascii_case("btc")
                    || req.msg.source_chain.eq_ignore_ascii_case("bitcoin");
                let dst_is_btc = req.msg.target_chain.eq_ignore_ascii_case("btc")
                    || req.msg.target_chain.eq_ignore_ascii_case("bitcoin");
                let is_same_chain = (src_is_tics && dst_is_tics) || (src_is_btc && dst_is_btc);
                let is_tics_to_btc = src_is_tics && dst_is_btc;

                let target_amount = if is_same_chain {
                    source_amount
                } else {
                    let prices = match crate::rpc_server::utils::fetch_crypto_prices(Some(
                        req.msg.timestamp,
                    ))
                    .await
                    {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(
                                "❌ [HTTP] Failed to fetch prices for intent {}: {}",
                                intent_hash_hex, e
                            );
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                intent_hash: intent_hash_hex.clone(),
                                error_message: Some(format!("Failed to fetch prices: {}", e)),
                                signer_eth_address: None,
                            }));
                        }
                    };
                    match crate::rpc_server::utils::convert_src_smallest_to_dst_smallest(
                        source_amount,
                        &req.msg.source_chain,
                        &req.msg.target_chain,
                        &prices,
                    ) {
                        Ok(amt) => amt,
                        Err(e) => {
                            warn!(
                                "❌ [HTTP] Failed to convert target amount for intent {}: {:?}",
                                intent_hash_hex, e
                            );
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                intent_hash: intent_hash_hex.clone(),
                                error_message: Some(format!(
                                    "Failed to compute target amount: {:?}",
                                    e
                                )),
                                signer_eth_address: None,
                            }));
                        }
                    }
                };

                // TICS->BTC minimum satoshi check
                const MIN_BTC_INTENT_SATS: u128 = 550;
                if is_tics_to_btc && target_amount < MIN_BTC_INTENT_SATS {
                    warn!(
                        "⚠️ [HTTP] TICS->BTC intent {} below minimum: {} satoshis (min {})",
                        intent_hash_hex, target_amount, MIN_BTC_INTENT_SATS
                    );
                    return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                        status: "error".to_string(),
                        intent_hash: intent_hash_hex.clone(),
                        error_message: Some(format!(
                            "TICS to BTC amount too small: converts to {} satoshis (minimum {} satoshis required)",
                            target_amount, MIN_BTC_INTENT_SATS
                        )),
                        signer_eth_address: None,
                    }));
                }

                // BTC->TICS minimum satoshi check (source amount must be above Bitcoin dust limit)
                if src_is_btc && source_amount < (DUST_LIMIT_SATS as u128) {
                    warn!(
                        "⚠️ [HTTP] BTC-source intent {} below dust limit: {} satoshis (min {})",
                        intent_hash_hex, source_amount, DUST_LIMIT_SATS
                    );
                    return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                        status: "error".to_string(),
                        intent_hash: intent_hash_hex.clone(),
                        error_message: Some(format!(
                            "BTC amount too small: {} satoshis is below Bitcoin dust limit (minimum {} satoshis required)",
                            source_amount, DUST_LIMIT_SATS
                        )),
                        signer_eth_address: None,
                    }));
                }

                // BTC source: verify user has enough *confirmed* UTXOs to cover the amount.
                // The balance check above uses total balance (may include unconfirmed funds).
                // During batch processing only confirmed UTXOs are used, so reject early if
                // there are not enough confirmed funds.
                if src_is_btc {
                    let is_testnet = crate::types::network::network_type().is_testnet();
                    match crate::utils::transaction::fetch_bitcoin_utxos(
                        &req.msg.source_address,
                        is_testnet,
                    )
                    .await
                    {
                        Ok(utxos) => {
                            let confirmed_balance: u128 = utxos
                                .iter()
                                .filter(|u| u.status.confirmed)
                                .map(|u| u.value as u128)
                                .sum();
                            // required_balance already includes amount + dynamic fee buffer + estimated BTC fee
                            if confirmed_balance < required_balance {
                                warn!(
                                    "⚠️ [HTTP] Insufficient confirmed UTXOs for intent {}: confirmed {} sats, needs {} (amount {} + dynamic fee {} + fee {})",
                                    intent_hash_hex, confirmed_balance, required_balance,
                                    source_amount, dynamic_fee_buffer, estimated_tx_fee
                                );
                                return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                    status: "error".to_string(),
                                    intent_hash: intent_hash_hex.clone(),
                                    error_message: Some(format!(
                                        "Insufficient confirmed balance: you have {} confirmed sats but need {} \
                                         (amount {} + dynamic fee buffer {} + estimated fee {}). \
                                         Please wait for your pending transactions to confirm.",
                                        confirmed_balance, required_balance,
                                        source_amount, dynamic_fee_buffer, estimated_tx_fee
                                    )),
                                    signer_eth_address: None,
                                }));
                            }
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [HTTP] Failed to fetch UTXOs for BTC source address {}: {}",
                                req.msg.source_address, e
                            );
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                intent_hash: intent_hash_hex.clone(),
                                error_message: Some(format!(
                                    "Failed to verify confirmed BTC balance: {}",
                                    e
                                )),
                                signer_eth_address: None,
                            }));
                        }
                    }
                }

                // Network balance check for ALL directions:
                // - *->TICS: Treasury vault balance >= target_amount (TICS payouts come from vault)
                // - *->BTC: DKG address balance on target chain >= target_amount
                let network_address = if dst_is_tics {
                    crate::env_defaults::treasury_vault_contract_address()
                } else {
                    // Use DKG group key to derive the network address on the target chain
                    match dkg_storage.get_final_public().await {
                        Ok(Some(final_public)) => {
                            if dst_is_btc {
                                match crate::utils::get_btc_address_from_group_key(final_public) {
                                    Ok(addr) => addr,
                                    Err(e) => {
                                        warn!("⚠️ [RPC] Failed to derive network BTC address: {}", e);
                                        String::new()
                                    }
                                }
                            } else {
                                crate::utils::get_eth_address_from_group_key(final_public)
                            }
                        }
                        _ => String::new(),
                    }
                };

                if !network_address.is_empty() {
                    let network_blockchain = if dst_is_btc { "btc" } else { "eth" };
                    match crate::rpc_server::utils::fetch_network_balance(
                        &network_address,
                        network_blockchain,
                    )
                    .await
                    {
                        Ok(network_balance) => {
                            if network_balance < target_amount {
                                let liquidity_source = if dst_is_tics {
                                    "treasury vault"
                                } else {
                                    "network"
                                };
                                warn!(
                                    "⚠️ [HTTP] Insufficient {} balance for intent {}: have {}, need {}",
                                    liquidity_source, intent_hash_hex, network_balance, target_amount
                                );
                                return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                    status: "error".to_string(),
                                    intent_hash: intent_hash_hex.clone(),
                                    error_message: Some(format!(
                                        "Insufficient network liquidity: {} has {} but need {} (in smallest units). Try again later.",
                                        liquidity_source, network_balance, target_amount
                                    )),
                                    signer_eth_address: None,
                                }));
                            }
                            info!(
                                "✅ [HTTP] Network has sufficient balance for intent: {} >= {}",
                                network_balance, target_amount
                            );
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [HTTP] Failed to fetch network balance for intent {}: {}",
                                intent_hash_hex, e
                            );
                            return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                                status: "error".to_string(),
                                intent_hash: intent_hash_hex.clone(),
                                error_message: Some(format!(
                                    "Failed to verify network liquidity: {}",
                                    e
                                )),
                                signer_eth_address: None,
                            }));
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [HTTP] Could not determine network address for intent {} (DKG key not available)",
                        intent_hash_hex
                    );
                    return Ok(warp::reply::json(&UserMpcDepositVerifyResponse {
                        status: "error".to_string(),
                        intent_hash: intent_hash_hex.clone(),
                        error_message: Some(
                            "Network not ready: DKG key not available to verify liquidity. Try again later.".to_string(),
                        ),
                        signer_eth_address: None,
                    }));
                }

                // NOTE: Do NOT store the intent here at RPC level.
                // Storage happens in the channel handler (local node) and gossipsub handler (peers).
                // Storing here would cause the channel handler's duplicate check to
                // block the gossipsub broadcast, so peers would never receive the intent.

                (user_reg, target_amount)
            }
        }
    };

    // UserToVault always requires user_tics_address
    let user_tics_address = user_registration.tics_address.clone();

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
        Some(user_tics_address),
        message_tx,
        transaction_type,
        dkg_storage.clone(),
        req.signature.clone(),
        computed_target_amount,
    )
    .await
    {
        Ok(_) => {
            info!(
                "✅ Deposit intent processed successfully for user: {}",
                user_registration.tics_address
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
                signer_eth_address: None,
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
        signer_eth_address: None,
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
            intent_status: None,
            source_address: None,
            target_address: None,
            source_chain: None,
            target_chain: None,
            amount: None,
            source_token: None,
            target_token: None,
            timestamp: None,
            user_to_network_tx_id: None,
            network_to_target_tx_id: None,
            final_solver_id: None,
            created_at: None,
            updated_at: None,
            error_message: Some("intent_hash is required".to_string()),
        }));
    }
    let intent = user_intent_manager.get_intent(intent_hash).await;
    let tx_ids = user_intent_manager
        .get_intent_transaction_ids(intent_hash)
        .await;
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
                intent_status: None,
                source_address: None,
                target_address: None,
                source_chain: None,
                target_chain: None,
                amount: None,
                source_token: None,
                target_token: None,
                timestamp: None,
                user_to_network_tx_id: None,
                network_to_target_tx_id: None,
                final_solver_id: None,
                created_at: None,
                updated_at: None,
                error_message: Some("Intent not found".to_string()),
            }))
        }
        Some(intent) => {
            let (
                user_to_network_tx_id,
                network_to_target_tx_id,
                final_solver_id,
                created_at,
                updated_at,
            ) = match &tx_ids {
                Some(ids) => (
                    ids.user_to_network_tx_id.clone(),
                    ids.network_to_target_tx_id.clone(),
                    ids.final_solver_id.clone(),
                    Some(ids.created_at.to_rfc3339()),
                    Some(ids.updated_at.to_rfc3339()),
                ),
                None => (None, None, None, None, None),
            };

            // Extract fields from intent for top-level access
            let source_address = Some(intent.source_address.clone());
            let target_address = Some(intent.target_address.clone());
            let source_chain = Some(intent.source_chain.clone());
            let target_chain = Some(intent.target_chain.clone());
            let amount = Some(intent.amount.clone());
            let source_token = Some(intent.source_token.clone());
            let target_token = Some(intent.target_token.clone());
            let timestamp = Some(intent.timestamp);

            Ok(warp::reply::json(&IntentDetailsResponse {
                status: "success".to_string(),
                intent_hash: intent_hash.to_string(),
                intent_status,
                source_address,
                target_address,
                source_chain,
                target_chain,
                amount,
                source_token,
                target_token,
                timestamp,
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
    tics_address: String,
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🔍 HTTP: Received user info request for address: {}",
        tics_address
    );

    let addr_cs = match super::errors::validate_tics_address(&tics_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!(
                "❌ HTTP: Address validation failed for '{}': {:?}",
                tics_address, e
            );
            let error_response = UserInfoResponse {
                status: "error".to_string(),
                user_id: None,
                tics_address: None,
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
                tics_address: Some(registration.tics_address),
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
                tics_address: None,
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

pub(crate) async fn handle_get_admin_info(
    tics_address: String,
    user_intent_manager: Arc<UserIntentManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    use crate::types::rpc_server::AdminInfoResponse;

    info!(
        "🔍 HTTP: Received admin info request for address: {}",
        tics_address
    );

    let addr_cs = match super::errors::validate_tics_address(&tics_address) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!(
                "❌ HTTP: Address validation failed for '{}': {:?}",
                tics_address, e
            );
            return Ok(warp::reply::json(&AdminInfoResponse {
                status: "error".to_string(),
                admin_id: None,
                tics_address: None,
                has_tweaked_share: None,
                has_group_key: None,
                derived_eth_address: None,
                derived_btc_address: None,
                created_at: None,
                error: Some(e.to_error_response()),
            }));
        }
    };

    match user_intent_manager.get_admin_by_address(&addr_cs).await {
        Some(admin) => {
            info!("✅ HTTP: Found admin info for {}", addr_cs);

            Ok(warp::reply::json(&AdminInfoResponse {
                status: "success".to_string(),
                admin_id: Some(admin.admin_id),
                tics_address: Some(admin.tics_address),
                has_tweaked_share: Some(admin.tweaked_secret_share.is_some()),
                has_group_key: Some(admin.user_group_key.is_some()),
                derived_eth_address: admin.derived_eth_address,
                derived_btc_address: admin.derived_btc_address,
                created_at: Some(admin.created_at.to_rfc3339()),
                error: None,
            }))
        }
        None => {
            info!("❌ HTTP: Admin not found for {}", addr_cs);

            Ok(warp::reply::json(&AdminInfoResponse {
                status: "error".to_string(),
                admin_id: None,
                tics_address: None,
                has_tweaked_share: None,
                has_group_key: None,
                derived_eth_address: None,
                derived_btc_address: None,
                created_at: None,
                error: Some(
                    RpcError::UserNotFound(format!("Admin with address {addr_cs} not found"))
                        .to_error_response(),
                ),
            }))
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
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("📊 HTTP: Received node info request");

    let dkg_status = if dkg_storage.is_initial_dkg_complete().await.unwrap_or(false) {
        "Completed"
    } else {
        "Pending"
    };

    let peer_indices = dkg_storage.get_all_peer_indices().ok();
    let peer_count = peer_indices.as_ref().map(|p| p.len()).unwrap_or(0);

    let multiaddr = {
        let (responder, receiver) = tokio::sync::oneshot::channel();
        if message_tx
            .lock()
            .await
            .send(ChannelMessage::NodeMultiaddrRequest { responder })
            .await
            .is_err()
        {
            None
        } else {
            tokio::time::timeout(Duration::from_secs(2), receiver)
                .await
                .ok()
                .and_then(|r| r.ok().flatten())
        }
    };

    info!(
        "✅ HTTP: Node info: peers={}, dkg={}, multiaddr={:?}",
        peer_count, dkg_status, multiaddr
    );

    Ok(warp::reply::json(&serde_json::json!({
        "node_id": node_id,
        "multiaddr": multiaddr,
        "status": "active",
        "dkg_status": dkg_status,
        "peer_count": peer_count,
        "peers": peer_indices.unwrap_or_default(),
        "capabilities": {
            "signing": true,
            "vrf": true
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
    info!(
        "📊 HTTP: pending_intents_count = {} (Pending: {}, Batched: {})",
        count,
        pending.len(),
        batched.len()
    );
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
    let rpc_url = crate::env_defaults::solver_contract_rpc_url();
    let contract_address = crate::env_defaults::solver_contract_address();
    let chain_id = crate::env_defaults::solver_contract_chain_id()
        .parse::<u64>()
        .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());

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

    let client = ContractClient::new(config.clone())
        .map_err(|e| format!("Failed to create contract client: {e}"))?;

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

/// Fetch unclaimed reward amounts for a solver from the on-chain SolverManager contract.
/// Uses SOLVER_CONTRACT_* env vars. Returns (btc_unclaimed, tics_unclaimed) as decimal strings.
async fn fetch_solver_unclaimed_rewards_from_contract(
    normalized_address: &str,
) -> Result<(String, String), String> {
    let rpc_url = crate::env_defaults::solver_contract_rpc_url();
    let contract_address = crate::env_defaults::solver_contract_address();
    let chain_id = crate::env_defaults::solver_contract_chain_id()
        .parse::<u64>()
        .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());

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

    let client = ContractClient::new(config.clone())
        .map_err(|e| format!("Failed to create contract client: {e}"))?;

    let solver_contract = SolverManagerContract::new(&config, client.provider())
        .map_err(|e| format!("Failed to create solver contract interface: {e}"))?;

    let solver_addr = normalized_address
        .parse::<Address>()
        .map_err(|e| format!("Invalid solver EVM address {normalized_address}: {e}"))?;

    let solver_id = solver_contract
        .get_solver_id(solver_addr)
        .await
        .map_err(|e| format!("Failed to get solver ID: {e}"))?;

    if solver_id.trim().is_empty() {
        return Err("Address is not a registered solver on the contract".to_string());
    }

    let rewards = solver_contract
        .get_solvers_unclaimed_rewards(vec![solver_id])
        .await
        .map_err(|e| format!("Failed to get unclaimed rewards: {e}"))?;

    let (btc, tics) = rewards
        .first()
        .map(|r| (r.1.to_string(), r.2.to_string()))
        .unwrap_or_else(|| ("0".to_string(), "0".to_string()));

    Ok((btc, tics))
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
    let (liquidity_btc, liquidity_tics) =
        match fetch_solver_liquidity_from_contract(&normalized_address).await {
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
            reward_btc: None,
            reward_tics: None,
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
                reward_btc: None,
                reward_tics: None,
                unclaimed_rewards: vec![],
                message: "Invalid solver address format".to_string(),
                error_message: Some(format!("Invalid address format: {e}")),
            }));
        }
    };

    // Fetch unclaimed reward amounts from the SolverManager contract.
    let (reward_btc, reward_tics) =
        match fetch_solver_unclaimed_rewards_from_contract(&normalized_address).await {
            Ok((btc, tics)) => (Some(btc), Some(tics)),
            Err(e) => {
                warn!(
                    "⚠️ [SOLVER_REWARDS] Failed to fetch contract rewards for {}: {}",
                    normalized_address, e
                );
                return Ok(warp::reply::json(&GetSolverRewardsResponse {
                    status: "error".to_string(),
                    solver_address: normalized_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    unclaimed_rewards: vec![],
                    message: e.clone(),
                    error_message: Some(e),
                }));
            }
        };

    let db = user_intent_manager.get_database();
    let prefix = format!(
        "pending_claim_reward:{}:",
        normalized_address.to_lowercase()
    );
    let entries: Vec<(String, PendingClaimRewardRequest)> = match db.get_values_with_prefix(&prefix)
    {
        Ok(e) => e,
        Err(e) => {
            warn!(
                "⚠️ [SOLVER_REWARDS] Failed to load pending claim rewards for solver {}: {}",
                normalized_address, e
            );
            return Ok(warp::reply::json(&GetSolverRewardsResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                reward_btc: reward_btc.clone(),
                reward_tics: reward_tics.clone(),
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
            tics_address: r.tics_address,
            btc_address: r.btc_address,
        })
        .collect();

    let count = unclaimed_rewards.len();
    info!(
        "✅ Solver {} has contract rewards BTC={}, TICS={}; {} pending claim request(s)",
        normalized_address,
        reward_btc.as_deref().unwrap_or("?"),
        reward_tics.as_deref().unwrap_or("?"),
        count
    );

    Ok(warp::reply::json(&GetSolverRewardsResponse {
        status: "success".to_string(),
        solver_address: normalized_address,
        reward_btc,
        reward_tics,
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
    _dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "🎁 HTTP: claim_reward request for TICS: {:?}, BTC: {:?}",
        req.tics_address, req.btc_address
    );
    if req.tics_address.is_none() && req.btc_address.is_none() {
        return Ok(warp::reply::json(&ClaimRewardResponse {
            status: "error".to_string(),
            tics_address: None,
            btc_address: None,
            reward_btc: None,
            reward_tics: None,
            message: "At least one address must be provided".to_string(),
            error_message: Some("Both tics_address and btc_address cannot be None".to_string()),
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
                tics_address: req.tics_address.clone(),
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
                error!(
                    "❌ Failed to recover address: personal_sign={}, raw={}",
                    e1, e2
                );
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
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

    let normalized_address = match checksum_from_any(&solver_address) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("❌ Invalid solver address format: {}", e);
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                tics_address: req.tics_address.clone(),
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

    info!(
        "🔐 Recovered solver address from signature: {}",
        normalized_address
    );

    // Reject if this solver already has a claim reward request in Pending or Batched (one in-flight per solver).
    {
        let db = user_intent_manager.get_database();
        let prefix = format!(
            "pending_claim_reward:{}:",
            normalized_address.to_lowercase()
        );
        let entries: Vec<(String, PendingClaimRewardRequest)> =
            match db.get_values_with_prefix(&prefix) {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                    "⚠️ [CLAIM_REWARD] Failed to check existing claim requests for solver {}: {}",
                    normalized_address, e
                );
                    return Ok(warp::reply::json(&ClaimRewardResponse {
                        status: "error".to_string(),
                        tics_address: req.tics_address.clone(),
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
                tics_address: req.tics_address.clone(),
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

    // Reject if solver has no unclaimed rewards on the contract (RPC-only check; no contract revert).
    {
        let rpc_url = crate::env_defaults::solver_contract_rpc_url();
        let contract_address = crate::env_defaults::solver_contract_address();
        let chain_id = crate::env_defaults::solver_contract_chain_id()
            .parse::<u64>()
            .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());
        let contract_addr = match contract_address.parse::<Address>() {
            Ok(a) => a,
            Err(e) => {
                warn!("⚠️ [CLAIM_REWARD] Invalid SOLVER_CONTRACT_ADDRESS: {}", e);
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Solver contract configuration error".to_string(),
                    error_message: Some("Invalid contract address".to_string()),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        };
        let config = ContractConfig {
            rpc_url: rpc_url.clone(),
            contract_address: contract_addr,
            chain_id,
        };
        let client = match ContractClient::new(config.clone()) {
            Ok(c) => c,
            Err(e) => {
                warn!("⚠️ [CLAIM_REWARD] Contract client failed: {}", e);
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Failed to check unclaimed rewards".to_string(),
                    error_message: Some("Contract client unavailable".to_string()),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        };
        let contract = match SolverManagerContract::new(&config, client.provider()) {
            Ok(c) => c,
            Err(e) => {
                warn!("⚠️ [CLAIM_REWARD] SolverManagerContract::new failed: {}", e);
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Failed to check unclaimed rewards".to_string(),
                    error_message: Some("Contract interface unavailable".to_string()),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        };
        let solver_addr = match normalized_address.parse::<Address>() {
            Ok(a) => a,
            Err(_) => {
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Invalid solver address".to_string(),
                    error_message: Some("Invalid solver address".to_string()),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        };
        let solver_id = match contract.get_solver_id(solver_addr).await {
            Ok(id) if !id.trim().is_empty() => id,
            Ok(_) => {
                info!(
                    "🚫 [CLAIM_REWARD] Rejecting claim for {}: not a registered solver",
                    normalized_address
                );
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Address is not a registered solver".to_string(),
                    error_message: Some("Not a registered solver".to_string()),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
            Err(e) => {
                warn!(
                    "⚠️ [CLAIM_REWARD] get_solver_id failed for {}: {}",
                    normalized_address, e
                );
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Failed to verify solver on contract".to_string(),
                    error_message: Some("Contract call failed".to_string()),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        };
        let rewards = match contract
            .get_solvers_unclaimed_rewards(vec![solver_id])
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "⚠️ [CLAIM_REWARD] get_solvers_unclaimed_rewards failed: {}",
                    e
                );
                return Ok(warp::reply::json(&ClaimRewardResponse {
                    status: "error".to_string(),
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
                    reward_btc: None,
                    reward_tics: None,
                    message: "Failed to fetch unclaimed rewards".to_string(),
                    error_message: Some("Contract call failed".to_string()),
                    tics_reward_tx_id: None,
                    btc_reward_tx_id: None,
                }));
            }
        };
        let (btc_unclaimed, tics_unclaimed) = rewards
            .first()
            .map(|r| (r.1, r.2))
            .unwrap_or((U256::zero(), U256::zero()));
        let wants_btc = req.btc_address.is_some();
        let wants_tics = req.tics_address.is_some();
        let btc_dust = U256::from(DUST_LIMIT_SATS);
        let min_tics = U256::from(MIN_CLAIM_TICS_WEI);
        if wants_btc && btc_unclaimed <= btc_dust {
            info!(
                "🚫 [CLAIM_REWARD] Rejecting claim for {}: BTC rewards below dust ({})",
                normalized_address, DUST_LIMIT_SATS
            );
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                reward_btc: None,
                reward_tics: None,
                message: "No BTC rewards available to claim (below dust threshold)".to_string(),
                error_message: Some("BTC reward below dust threshold".to_string()),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
        if wants_tics && tics_unclaimed <= min_tics {
            info!(
                "🚫 [CLAIM_REWARD] Rejecting claim for {}: TICS rewards not above 1 TICS",
                normalized_address
            );
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                reward_btc: None,
                reward_tics: None,
                message: "No TICS rewards available to claim (minimum 1 TICS)".to_string(),
                error_message: Some("TICS reward must be above 1 TICS".to_string()),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
    }

    let request_id = Uuid::new_v4().to_string();
    let pending = PendingClaimRewardRequest {
        request_id: request_id.clone(),
        solver_address: normalized_address.clone(),
        tics_address: req.tics_address.clone(),
        btc_address: req.btc_address.clone(),
        message: req.message.clone(),
        signature: req.signature.clone(),
        tx_id: None,
        status: "Pending".to_string(),
    };

    // Write to the local DB *before* broadcasting, mirroring the withdraw_liquidity pattern.
    // This closes the window where two concurrent RPC calls both pass the in-flight guard
    // and then race to be the first gossip write.  The gossip loopback on this node will
    // see the key already present and skip the redundant write (C-4 fix).
    let db_key = format!(
        "pending_claim_reward:{}:{}",
        normalized_address.to_lowercase(),
        request_id
    );
    let conflict_prefix = format!(
        "pending_claim_reward:{}:",
        normalized_address.to_lowercase()
    );
    let db = user_intent_manager.get_database();

    // Status-aware atomic reserve: only conflict on Pending/Batched records.
    // Completed records are ignored so a finished claim never blocks the next one.
    let db_clone = db.clone();
    let pending_clone = pending.clone();
    let db_key_clone = db_key.clone();
    let conflict_prefix_clone = conflict_prefix.clone();
    let reserve_result = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let existing = db_clone
            .get_values_with_prefix::<crate::types::rpc_server::PendingClaimRewardRequest>(
                &conflict_prefix_clone,
            )?;
        let has_active = existing
            .iter()
            .any(|(_, r)| r.status == "Pending" || r.status == "Batched");
        if has_active {
            return Ok(false);
        }
        db_clone.put_string(&db_key_clone, &pending_clone)?;
        Ok(true)
    })
    .await;

    match reserve_result {
        Ok(Ok(true)) => {
            info!(
                "🔒 [CLAIM_REWARD] Atomically reserved request {} for solver {}",
                request_id, normalized_address
            );
        }
        Ok(Ok(false)) => {
            warn!(
                "🚫 [CLAIM_REWARD] Atomic reserve rejected for solver {}: concurrent claim detected",
                normalized_address
            );
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                reward_btc: None,
                reward_tics: None,
                message: "A claim reward request is already in progress. Wait for it to complete.".to_string(),
                error_message: Some("Concurrent request detected".to_string()),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
        Ok(Err(e)) => {
            warn!(
                "⚠️ [CLAIM_REWARD] DB error during atomic reserve for solver {}: {}",
                normalized_address, e
            );
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                reward_btc: None,
                reward_tics: None,
                message: "Failed to reserve claim reward request slot".to_string(),
                error_message: Some(format!("Database error: {}", e)),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
        Err(e) => {
            warn!(
                "⚠️ [CLAIM_REWARD] Task error during atomic reserve for solver {}: {}",
                normalized_address, e
            );
            return Ok(warp::reply::json(&ClaimRewardResponse {
                status: "error".to_string(),
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                reward_btc: None,
                reward_tics: None,
                message: "Failed to reserve claim reward request slot".to_string(),
                error_message: Some(format!("Task error: {}", e)),
                tics_reward_tx_id: None,
                btc_reward_tx_id: None,
            }));
        }
    }

    let broadcast = ChannelMessage::PendingClaimRewardRequestBroadcast {
        request: pending.clone(),
    };
    if let Err(e) = message_tx.lock().await.send(broadcast).await {
        warn!(
            "⚠️ Failed to broadcast claim_reward request {} to other nodes: {}",
            request_id, e
        );
    } else {
        info!(
            "📡 Broadcast claim_reward request {} to other nodes for DB sync",
            request_id
        );
    }

    info!(
        "✅ Enqueued claim_reward request {} for solver {}",
        request_id, normalized_address
    );

    Ok(warp::reply::json(&ClaimRewardResponse {
        status: "success".to_string(),
        tics_address: req.tics_address.clone(),
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
    _dkg_storage: Arc<DkgStorage>,
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
                tics_address: req.tics_address.clone(),
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
                    tics_address: req.tics_address.clone(),
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
                tics_address: req.tics_address.clone(),
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
                    tics_address: req.tics_address.clone(),
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
            tics_address: req.tics_address.clone(),
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
        let solver_contract_address = crate::env_defaults::solver_contract_address();
        let solver_contract_rpc = crate::env_defaults::solver_contract_rpc_url();
        let solver_contract_chain_id = crate::env_defaults::solver_contract_chain_id()
            .parse::<u64>()
            .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());

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
                    tics_address: req.tics_address.clone(),
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
                    tics_address: req.tics_address.clone(),
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

    // Reject BTC withdrawals that cannot cover fee + dust
    if let Some(ref btc_amount_str) = withdraw_btc_amount {
        const BTC_DUST_SATS: u64 = 546;
        // Minimum fee: base_overhead(100) + 1 output(34) + 1 input(150)
        const BTC_MIN_FEE_SATS: u64 = 284;
        const BTC_MIN_WITHDRAW_SATS: u64 = BTC_DUST_SATS + BTC_MIN_FEE_SATS; // 830
        let amount_sats: u64 = btc_amount_str.parse().unwrap_or(0);
        if amount_sats < BTC_MIN_WITHDRAW_SATS {
            let msg = format!(
                "Minimum BTC withdraw amount is 0.0000083 BTC ({} sats).",
                BTC_MIN_WITHDRAW_SATS
            );
            info!(
                "🚫 [WITHDRAW_LIQUIDITY] BTC amount too low for solver {}: {} sats < required {} sats \
                (dust={} + min_fee={})",
                normalized_address, amount_sats, BTC_MIN_WITHDRAW_SATS, BTC_DUST_SATS, BTC_MIN_FEE_SATS
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                liquidity_btc: liquidity_btc_str.clone(),
                liquidity_tics: liquidity_tics_str.clone(),
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: msg.clone(),
                error_message: Some(msg),
            }));
        }
    }

    if withdraw_tics_amount.is_some() && withdraw_btc_amount.is_some() {
        let msg =
            "Only one liquidity type can be withdrawn per request. Provide amount_tics or amount_btc."
                .to_string();
        return Ok(warp::reply::json(&WithdrawLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address.clone(),
            liquidity_btc: liquidity_btc_str.clone(),
            liquidity_tics: liquidity_tics_str.clone(),
            tics_address: req.tics_address.clone(),
            btc_address: req.btc_address.clone(),
            tics_withdraw_tx_id: None,
            btc_withdraw_tx_id: None,
            message: msg.clone(),
            error_message: Some(msg),
        }));
    }

    if withdraw_tics_amount.is_some() && req.tics_address.is_none() {
        let msg = "TICS address is required to withdraw TICS liquidity".to_string();
        return Ok(warp::reply::json(&WithdrawLiquidityResponse {
            status: "error".to_string(),
            solver_address: normalized_address.clone(),
            liquidity_btc: liquidity_btc_str.clone(),
            liquidity_tics: liquidity_tics_str.clone(),
            tics_address: req.tics_address.clone(),
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
            tics_address: req.tics_address.clone(),
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
    // Reject if this solver already has a withdraw request for the same asset in Pending or Batched status
    // (one in-flight withdraw per solver per asset; persists over gossip so no duplicate on any node).
    {
        let withdraw_asset = if withdraw_tics_amount.is_some() {
            "TICS"
        } else {
            "BTC"
        };
        let db = user_intent_manager.get_database();
        let prefix = format!(
            "pending_withdraw_liquidity:{}:",
            normalized_address.to_lowercase()
        );
        let entries: Vec<(String, PendingWithdrawRequest)> = match db
            .get_values_with_prefix(&prefix)
        {
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
                    tics_address: req.tics_address.clone(),
                    btc_address: req.btc_address.clone(),
                    tics_withdraw_tx_id: None,
                    btc_withdraw_tx_id: None,
                    message: "Failed to check existing withdraw requests".to_string(),
                    error_message: Some("Database error".to_string()),
                }));
            }
        };
        let has_pending_or_batched = entries.iter().any(|(_, r)| {
            r.asset == withdraw_asset && (r.status == "Pending" || r.status == "Batched")
        });
        if has_pending_or_batched {
            info!(
                "🚫 [WITHDRAW_LIQUIDITY] Rejecting {} withdraw for solver {}: already has a {} request in Pending/Batched",
                withdraw_asset, normalized_address, withdraw_asset
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address.clone(),
                liquidity_btc: liquidity_btc_str.clone(),
                liquidity_tics: liquidity_tics_str.clone(),
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: format!("You already have a {} withdraw request in progress (Pending or Batched). Wait for it to complete.", withdraw_asset),
                error_message: Some(format!("One {} withdraw request at a time per solver", withdraw_asset)),
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
            tics_address: req.tics_address.clone(),
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
        tics_address: req.tics_address.clone(),
        btc_address: req.btc_address.clone(),
        message: req.message.clone(),
        // Carry the original signature so every gossip recipient can independently
        // re-verify the solver's identity before storing this request in RocksDB.
        signature: req.signature.clone(),
        tx_id: None,
        status: "Pending".to_string(),
    };

    // --- Atomic pre-write (closes TOCTOU between the guard check above and this write) ---
    //
    // The earlier guard (line ~3185) read the DB to confirm no Pending/Batched request exists.
    // Between that read and this write, a concurrent RPC call on this node (or a gossip message
    // arriving from another node) could also pass the guard and create a second request for the
    // same solver+asset.  Writing to the DB *before* broadcasting closes this local-node window:
    // if another call raced in, put_string_if_absent_async will find the prefix occupied and abort.
    //
    // put_string_if_absent_async wraps the prefix scan AND the conditional write inside a single
    // spawn_blocking closure, preventing the Tokio runtime from yielding between the two steps.
    // Using the synchronous variant would block the async runtime thread and still allow a race
    // on multi-threaded Tokio schedulers.  Cross-node races are bounded by gossip propagation
    // and resolved by Guard 2 in the gossip handler (gossipsub_handler.rs:5946).
    // Key is scoped to solver+asset so a pending TICS withdraw does not block a BTC
    // withdraw and vice versa.
    let db_key = format!(
        "pending_withdraw_liquidity:{}:{}:{}",
        normalized_address.to_lowercase(),
        asset.to_lowercase(),
        request_id
    );
    let conflict_prefix = format!(
        "pending_withdraw_liquidity:{}:{}:",
        normalized_address.to_lowercase(),
        asset.to_lowercase()
    );
    let db = user_intent_manager.get_database();

    // Status-aware atomic reserve: scan the per-asset prefix and only conflict on
    // Pending/Batched records.  Completed records are ignored so a finished withdraw
    // never blocks the next one.  Runs inside spawn_blocking so the scan+write pair
    // has no async yield point, preserving the same TOCTOU safety as before.
    let db_clone = db.clone();
    let pending_clone = pending.clone();
    let db_key_clone = db_key.clone();
    let conflict_prefix_clone = conflict_prefix.clone();
    let reserve_result = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let existing = db_clone
            .get_values_with_prefix::<crate::types::rpc_server::PendingWithdrawRequest>(
                &conflict_prefix_clone,
            )?;
        let has_active = existing
            .iter()
            .any(|(_, r)| r.status == "Pending" || r.status == "Batched");
        if has_active {
            return Ok(false);
        }
        db_clone.put_string(&db_key_clone, &pending_clone)?;
        Ok(true)
    })
    .await;

    match reserve_result {
        Ok(Ok(true)) => {
            info!(
                "🔒 [WITHDRAW_LIQUIDITY] Atomically reserved request {} for solver {} (asset={}, amount={})",
                request_id, normalized_address, asset, amount
            );
        }
        Ok(Ok(false)) => {
            // A concurrent Pending/Batched request exists for the same solver+asset.
            warn!(
                "🚫 [WITHDRAW_LIQUIDITY] Atomic reserve rejected for solver {}: a {} request already exists (concurrent race detected)",
                normalized_address, asset
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: liquidity_btc_str,
                liquidity_tics: liquidity_tics_str,
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: format!(
                    "A {} withdraw request is already pending. Wait for it to complete.",
                    asset
                ),
                error_message: Some("Concurrent request detected".to_string()),
            }));
        }
        Ok(Err(e)) => {
            warn!(
                "⚠️ [WITHDRAW_LIQUIDITY] DB error during atomic reserve for solver {}: {}",
                normalized_address, e
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: liquidity_btc_str,
                liquidity_tics: liquidity_tics_str,
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Failed to reserve withdraw request slot".to_string(),
                error_message: Some(format!("Database error: {}", e)),
            }));
        }
        Err(e) => {
            warn!(
                "⚠️ [WITHDRAW_LIQUIDITY] Task error during atomic reserve for solver {}: {}",
                normalized_address, e
            );
            return Ok(warp::reply::json(&WithdrawLiquidityResponse {
                status: "error".to_string(),
                solver_address: normalized_address,
                liquidity_btc: liquidity_btc_str,
                liquidity_tics: liquidity_tics_str,
                tics_address: req.tics_address.clone(),
                btc_address: req.btc_address.clone(),
                tics_withdraw_tx_id: None,
                btc_withdraw_tx_id: None,
                message: "Failed to reserve withdraw request slot".to_string(),
                error_message: Some(format!("Task error: {}", e)),
            }));
        }
    }

    // Record is now in this node's DB.  Broadcast to peers so they also store it.
    // The gossip handler on *this* node will see the record already present (Guard 2) and
    // skip it; peer nodes will accept and persist it via the normal gossip path.
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
        tics_address: req.tics_address.clone(),
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

    info!(
        "💧 HTTP: add_liquidity request with message: {}",
        req.message
    );

    // 1) Load VERIFICATION_ADDRESS from env (must NOT be hardcoded).
    let verification_address_raw = crate::env_defaults::verification_address();
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

    match payload.amount.trim().parse::<u128>() {
        Ok(a) if a > 0 => {} // valid
        Ok(_) => {
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                message: "Amount must be greater than zero".to_string(),
                error_message: Some("amount must be non-zero".to_string()),
            }));
        }
        Err(_) => {
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                message: "Invalid amount format".to_string(),
                error_message: Some("amount must be a valid decimal integer string".to_string()),
            }));
        }
    }

    // Validate chainId before persisting (must match RPC rules: 0 = BTC, TICS chain ID = EVM).
    let tics_chain_id = crate::env_defaults::mpc_tics_chain_id();
    if payload.chain_id != 0 && payload.chain_id != tics_chain_id {
        warn!(
            "⚠️ [ADD_LIQUIDITY] Unsupported chain_id {} for add_liquidity request, rejecting (allowed: 0=BTC, {}=EVM)",
            payload.chain_id, tics_chain_id
        );
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            message: "Unsupported chainId".to_string(),
            error_message: Some(format!(
                "chainId must be 0 (BTC) or {} (EVM)",
                tics_chain_id
            )),
        }));
    }

    // Validate solver_id is non-empty
    if payload.solver_id.trim().is_empty() {
        warn!("❌ [ADD_LIQUIDITY] Empty solver_id in payload");
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            message: "solver_id is required".to_string(),
            error_message: Some("solverId must be a non-empty string".to_string()),
        }));
    }

    // Validate solver_address is a valid Ethereum address
    if let Err(e) = super::errors::validate_tics_address(&payload.solver_address) {
        warn!(
            "❌ [ADD_LIQUIDITY] Invalid solver_address '{}': {:?}",
            payload.solver_address, e
        );
        return Ok(warp::reply::json(&AddLiquidityResponse {
            status: "error".to_string(),
            message: "Invalid solver address format".to_string(),
            error_message: Some(
                "solverAddress must be a valid Ethereum address (0x + 40 hex chars)".to_string(),
            ),
        }));
    }

    // Verify solver is onboarded (registered) on-chain
    match crate::contract::validate_solver_onboarded(&payload.solver_id, "ADD_LIQUIDITY").await {
        Ok(true) => {} // solver is onboarded
        Ok(false) => {
            warn!(
                "❌ [ADD_LIQUIDITY] Solver '{}' is not onboarded on-chain",
                payload.solver_id
            );
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                message: "Solver is not onboarded".to_string(),
                error_message: Some(format!(
                    "Solver '{}' is not onboarded on the solver contract",
                    payload.solver_id
                )),
            }));
        }
        Err(e) => {
            warn!(
                "❌ [ADD_LIQUIDITY] Failed to verify solver '{}' on-chain: {}",
                payload.solver_id, e
            );
            return Ok(warp::reply::json(&AddLiquidityResponse {
                status: "error".to_string(),
                message: "Solver verification failed".to_string(),
                error_message: Some(format!("Failed to verify solver on-chain: {e}")),
            }));
        }
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
                tx_id: req.tx_id.clone(),
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
            error!(
                "❌ [RPC] Failed to get liquidity operator share pubkey: {}",
                e
            );
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
                    user_tics_address: user_addr,
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
            user_info.user_tics_address, user_info.share_pubkey
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
            match crate::utils::get_btc_address_from_group_key(final_public) {
                Ok(btc_addr) => Some(crate::types::rpc_server::AddressInfo {
                    eth_address: eth_addr,
                    btc_address: btc_addr,
                }),
                Err(e) => {
                    error!("❌ [RPC] Failed to derive BTC address from network group key: {}", e);
                    None
                }
            }
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
            let eth_addr =
                crate::utils::get_eth_address_from_group_key(liquidity_operator_group_key);
            match crate::utils::get_btc_address_from_group_key(liquidity_operator_group_key) {
                Ok(btc_addr) => Some(crate::types::rpc_server::AddressInfo {
                    eth_address: eth_addr,
                    btc_address: btc_addr,
                }),
                Err(e) => {
                    error!("❌ [RPC] Failed to derive BTC address from liquidity operator group key: {}", e);
                    None
                }
            }
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
            "📍 [RPC] Network Addresses: TICS={}, BTC={}",
            net_addrs.eth_address, net_addrs.btc_address
        );
    }
    if let Some(ref liquidity_operator_addrs) = liquidity_operator_addresses {
        info!(
            "📍 [RPC] Liquidity Operator Addresses: TICS={}, BTC={}",
            liquidity_operator_addrs.eth_address, liquidity_operator_addrs.btc_address
        );
    }

    Ok(warp::reply::json(
        &crate::types::rpc_server::GetNetworkAddressesResponse {
            status: "success".to_string(),
            network_addresses,
            liquidity_operator_addresses,
            vault_address: crate::env_defaults::treasury_vault_contract_address(),
            message: "Retrieved network addresses (same across all nodes)".to_string(),
            error_message: None,
        },
    ))
}

pub(crate) async fn handle_rejoin_status(
    solver_id: String,
    database: Arc<Database>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let prefix = format!(
        "{}{}",
        crate::database::keys::PENDING_DISCONNECTION,
        solver_id
    );

    let pending_keys = database
        .get_keys_with_prefix_async(&prefix)
        .await
        .unwrap_or_default();

    let blocked = !pending_keys.is_empty();
    let pending_records = pending_keys.len();

    let message = if blocked {
        format!(
            "Node {} is blocked from rejoining — {} pending invalidation transaction(s) must complete first",
            solver_id, pending_records
        )
    } else {
        format!("Node {} is clear to rejoin the network", solver_id)
    };

    info!(
        "📋 [REJOIN_STATUS] solver_id={}, blocked={}, pending_records={}",
        solver_id, blocked, pending_records
    );

    Ok(warp::reply::json(&RejoinStatusResponse {
        solver_id,
        blocked,
        pending_records,
        message,
    }))
}

pub(crate) async fn handle_check_peer_connection(
    peer_id: String,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let (responder, receiver) = tokio::sync::oneshot::channel();
    {
        let tx = message_tx.lock().await;
        tx.send(ChannelMessage::PeerConnectionCheck {
            peer_id: peer_id.clone(),
            responder,
        })
        .await
        .map_err(|e| {
            warp::reject::custom(super::errors::RpcError::InternalError(format!(
                "Failed to send peer connection check: {e}"
            )))
        })?;
    }

    let connected = tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .map_err(|_| {
            warp::reject::custom(super::errors::RpcError::Timeout(
                "Timed out checking peer connection".to_string(),
            ))
        })
        .and_then(|res| {
            res.map_err(|e| {
                warp::reject::custom(super::errors::RpcError::InternalError(format!(
                    "Failed to receive peer connection status: {e}"
                )))
            })
        })?;

    Ok(warp::reply::json(&PeerConnectionResponse {
        peer_id,
        connected,
    }))
}

/// POST /claim_platform_fee — admin-only endpoint.
///
/// Verifies the request was signed by `VERIFICATION_ADDRESS`, validates that
/// exactly one of `tics_target_address` or `btc_target_address` is supplied,
/// stores a `PendingClaimPlatformFeeRequest` in every node's RocksDB via
/// gossipsub broadcast, and returns `status: "pending"`.
///
/// Processing (signing, on-chain submission) is handled separately once the
/// request is in the `Pending` state across all nodes.
pub(crate) async fn handle_claim_platform_fee(
    req: ClaimPlatformFeeRequest,
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
    db: Arc<crate::database::Database>,
    user_intent_manager: Arc<crate::user_intent_manager::UserIntentManager>,
    dkg_storage: Arc<DkgStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!(
        "💰 HTTP: claim_platform_fee request — amount={}, tics_target={:?}, btc_target={:?}",
        req.amount, req.tics_target_address, req.btc_target_address
    );

    // --- 1. Validate exactly one address is provided ---
    match (&req.tics_target_address, &req.btc_target_address) {
        (Some(_), Some(_)) => {
            warn!("❌ [PLATFORM_FEE] Both tics_target_address and btc_target_address provided");
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "Only one target address may be provided per request".to_string(),
                error_message: Some(
                    "Provide either tics_target_address or btc_target_address, not both"
                        .to_string(),
                ),
            }));
        }
        (None, None) => {
            warn!("❌ [PLATFORM_FEE] Neither tics_target_address nor btc_target_address provided");
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: None,
                btc_target_address: None,
                message: "A target address is required".to_string(),
                error_message: Some(
                    "Provide exactly one of tics_target_address or btc_target_address".to_string(),
                ),
            }));
        }
        _ => {}
    }

    // --- 1b. Validate target address format ---
    if let Some(ref tics_addr) = req.tics_target_address {
        if let Err(e) = super::errors::validate_tics_address(tics_addr) {
            warn!(
                "❌ [PLATFORM_FEE] Invalid tics_target_address '{}': {:?}",
                tics_addr, e
            );
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "Invalid TICS target address format".to_string(),
                error_message: Some(
                    "tics_target_address must be a valid Ethereum address (0x + 40 hex chars)"
                        .to_string(),
                ),
            }));
        }
    }
    if let Some(ref btc_addr) = req.btc_target_address {
        if !crate::utils::is_valid_bitcoin_address(btc_addr) {
            warn!(
                "❌ [PLATFORM_FEE] Invalid btc_target_address '{}'",
                btc_addr
            );
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "Invalid BTC target address format".to_string(),
                error_message: Some(
                    "btc_target_address must be a syntactically valid Bitcoin address".to_string(),
                ),
            }));
        }
    }

    // --- 2. Validate amount ---
    let parsed_amount_u128: u128 = match req.amount.trim().parse::<u128>() {
        Ok(a) if a > 0 => a,
        Ok(_) => {
            warn!("❌ [PLATFORM_FEE] Zero amount: {}", req.amount);
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "Amount must be greater than zero".to_string(),
                error_message: Some("amount must be a non-zero decimal string".to_string()),
            }));
        }
        Err(_) => {
            warn!("❌ [PLATFORM_FEE] Invalid amount format: {}", req.amount);
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "Invalid amount format".to_string(),
                error_message: Some("amount must be a valid non-zero decimal string".to_string()),
            }));
        }
    };

    // --- 2b. BTC dust check: reject BTC claims below Bitcoin dust limit ---
    if req.btc_target_address.is_some() {
        if parsed_amount_u128 < (DUST_LIMIT_SATS as u128) {
            warn!(
                "❌ [PLATFORM_FEE] BTC claim amount {} sats below dust limit {}",
                parsed_amount_u128, DUST_LIMIT_SATS
            );
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "BTC amount below dust threshold".to_string(),
                error_message: Some(format!(
                    "BTC amount {} satoshis is below Bitcoin dust limit (minimum {} satoshis required)",
                    parsed_amount_u128, DUST_LIMIT_SATS
                )),
            }));
        }
    }

    // --- 3. Load ADMIN_PUBLIC_ADDRESS from env (or default) and verify admin signature ---
    let admin_public_address = crate::env_defaults::admin_public_address()
        .trim()
        .to_string();
    if admin_public_address.is_empty() {
        warn!("❌ [PLATFORM_FEE] ADMIN_PUBLIC_ADDRESS not configured");
        return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
            status: "error".to_string(),
            request_id: None,
            amount: req.amount.clone(),
            tics_target_address: req.tics_target_address.clone(),
            btc_target_address: req.btc_target_address.clone(),
            message: "ADMIN_PUBLIC_ADDRESS not configured".to_string(),
            error_message: Some("ADMIN_PUBLIC_ADDRESS env var is missing".to_string()),
        }));
    }

    let (compact, v) = match normalize_eth_signature(&req.signature) {
        Ok(t) => t,
        Err(e) => {
            warn!("❌ [PLATFORM_FEE] Invalid signature format: {}", e);
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
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
                    "❌ [PLATFORM_FEE] Failed to recover admin address: personal_sign={}, raw={}",
                    e1, e2
                );
                return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                    status: "error".to_string(),
                    request_id: None,
                    amount: req.amount.clone(),
                    tics_target_address: req.tics_target_address.clone(),
                    btc_target_address: req.btc_target_address.clone(),
                    message: "Failed to recover signature".to_string(),
                    error_message: Some(format!(
                        "Failed to recover signature: personal_sign={e1}, raw={e2}"
                    )),
                }));
            }
        },
    };

    if recovered_address.to_lowercase() != admin_public_address.to_lowercase() {
        warn!(
            "❌ [PLATFORM_FEE] Unauthorized: recovered={}, expected ADMIN_PUBLIC_ADDRESS={}",
            recovered_address, admin_public_address
        );
        return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
            status: "error".to_string(),
            request_id: None,
            amount: req.amount.clone(),
            tics_target_address: req.tics_target_address.clone(),
            btc_target_address: req.btc_target_address.clone(),
            message: "Unauthorized claim_platform_fee request".to_string(),
            error_message: Some("Recovered signer does not match ADMIN_PUBLIC_ADDRESS".to_string()),
        }));
    }

    // --- 3b. Verify admin is registered in MPC system ---
    let admin_address_cs = match admin_public_address.parse::<Address>() {
        Ok(addr) => ethers::utils::to_checksum(&addr, None),
        Err(e) => {
            error!(
                "❌ [PLATFORM_FEE] ADMIN_PUBLIC_ADDRESS '{}' is not a valid address: {}",
                admin_public_address, e
            );
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "ADMIN_PUBLIC_ADDRESS configuration is invalid".to_string(),
                error_message: Some(
                    "ADMIN_PUBLIC_ADDRESS env var is not a valid Ethereum address".to_string(),
                ),
            }));
        }
    };
    match user_intent_manager
        .get_admin_by_address(&admin_address_cs)
        .await
    {
        Some(admin) => {
            if admin.derived_eth_address.is_none() || admin.tweaked_secret_share.is_none() {
                warn!(
                    "❌ [PLATFORM_FEE] Admin {} is registered but missing derived address or tweaked share",
                    admin_address_cs
                );
                return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                    status: "error".to_string(),
                    request_id: None,
                    amount: req.amount.clone(),
                    tics_target_address: req.tics_target_address.clone(),
                    btc_target_address: req.btc_target_address.clone(),
                    message: "Admin registration incomplete".to_string(),
                    error_message: Some(
                        "Admin is registered but missing derived address or tweaked share. \
                         Wait for MPC key generation to complete or re-register."
                            .to_string(),
                    ),
                }));
            }
        }
        None => {
            warn!(
                "❌ [PLATFORM_FEE] Admin {} is not registered in MPC system",
                admin_address_cs
            );
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "Admin not registered in MPC system".to_string(),
                error_message: Some(
                    "Admin address is not registered. Call /register_admin first.".to_string(),
                ),
            }));
        }
    }

    // --- 4. Validate requested amount against on-chain unclaimed balance ---
    let asset = if req.tics_target_address.is_some() {
        "TICS"
    } else {
        "BTC"
    };

    // chainId: 0 for BTC, TICS chain ID for TICS (matches contract REQUIRED_CHAIN_BTC / REQUIRED_CHAIN_TICS)
    let on_chain_id: u64 = if asset == "BTC" {
        0
    } else {
        crate::env_defaults::mpc_tics_chain_id()
    };

    let requested_amount = match req.amount.trim().parse::<u128>() {
        Ok(a) => ethers::types::U256::from(a),
        Err(_) => {
            warn!(
                "❌ [PLATFORM_FEE] Cannot parse amount '{}' as u128",
                req.amount
            );
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: "Invalid amount format".to_string(),
                error_message: Some("amount must be a valid decimal integer string".to_string()),
            }));
        }
    };

    {
        let rpc_url = crate::env_defaults::solver_contract_rpc_url();
        let contract_address_str = crate::env_defaults::solver_contract_address();
        let chain_id = crate::env_defaults::solver_contract_chain_id()
            .parse::<u64>()
            .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());

        let contract_addr: Address = match contract_address_str.parse() {
            Ok(a) => a,
            Err(e) => {
                warn!("⚠️ [PLATFORM_FEE] Invalid SOLVER_CONTRACT_ADDRESS: {}", e);
                return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                    status: "error".to_string(),
                    request_id: None,
                    amount: req.amount.clone(),
                    tics_target_address: req.tics_target_address.clone(),
                    btc_target_address: req.btc_target_address.clone(),
                    message: "Solver contract configuration error".to_string(),
                    error_message: Some("Invalid contract address".to_string()),
                }));
            }
        };

        let config = ContractConfig {
            rpc_url,
            contract_address: contract_addr,
            chain_id,
        };
        let client = match ContractClient::new(config.clone()) {
            Ok(c) => c,
            Err(e) => {
                warn!("⚠️ [PLATFORM_FEE] Contract client failed: {}", e);
                return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                    status: "error".to_string(),
                    request_id: None,
                    amount: req.amount.clone(),
                    tics_target_address: req.tics_target_address.clone(),
                    btc_target_address: req.btc_target_address.clone(),
                    message: "Failed to connect to solver contract".to_string(),
                    error_message: Some("Contract client unavailable".to_string()),
                }));
            }
        };
        let contract = match SolverManagerContract::new(&config, client.provider()) {
            Ok(c) => c,
            Err(e) => {
                warn!("⚠️ [PLATFORM_FEE] SolverManagerContract::new failed: {}", e);
                return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                    status: "error".to_string(),
                    request_id: None,
                    amount: req.amount.clone(),
                    tics_target_address: req.tics_target_address.clone(),
                    btc_target_address: req.btc_target_address.clone(),
                    message: "Failed to initialize solver contract".to_string(),
                    error_message: Some("Contract interface unavailable".to_string()),
                }));
            }
        };

        let unclaimed = match contract
            .get_platform_unclaimed_fee(ethers::types::U256::from(on_chain_id))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "⚠️ [PLATFORM_FEE] getPlatformUnclaimedFee call failed: {}",
                    e
                );
                return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                    status: "error".to_string(),
                    request_id: None,
                    amount: req.amount.clone(),
                    tics_target_address: req.tics_target_address.clone(),
                    btc_target_address: req.btc_target_address.clone(),
                    message: "Failed to query on-chain unclaimed platform fee".to_string(),
                    error_message: Some(format!("getPlatformUnclaimedFee failed: {e}")),
                }));
            }
        };

        info!(
            "📊 [PLATFORM_FEE] On-chain unclaimed {} fee: {}, requested: {}",
            asset, unclaimed, requested_amount
        );

        if requested_amount > unclaimed {
            warn!(
                "❌ [PLATFORM_FEE] Requested amount {} exceeds unclaimed {} fee {} on-chain",
                requested_amount, asset, unclaimed
            );
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: format!(
                    "Requested amount exceeds available unclaimed {} platform fee",
                    asset
                ),
                error_message: Some(format!(
                    "Requested {} but only {} is available on-chain",
                    requested_amount, unclaimed
                )),
            }));
        }
    }

    // --- 4b. Verify network has sufficient balance for the claim ---
    // TICS claims: check treasury vault balance
    // BTC claims: check DKG-derived BTC address balance
    {
        let requested_u128 = parsed_amount_u128;
        let (network_address, blockchain, liquidity_source) = if asset == "TICS" {
            let vault_address = crate::env_defaults::treasury_vault_contract_address();
            (vault_address, "eth", "treasury vault")
        } else {
            // BTC: derive network address from DKG group key
            match dkg_storage.get_final_public().await {
                Ok(Some(final_public)) => {
                    match crate::utils::get_btc_address_from_group_key(final_public) {
                        Ok(btc_addr) => (btc_addr, "btc", "network BTC address"),
                        Err(e) => {
                            warn!("⚠️ [PLATFORM_FEE] Failed to derive BTC address from group key: {}", e);
                            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                                status: "error".to_string(),
                                request_id: None,
                                amount: req.amount.clone(),
                                tics_target_address: req.tics_target_address.clone(),
                                btc_target_address: req.btc_target_address.clone(),
                                message: "Network not ready: BTC address derivation failed".to_string(),
                                error_message: Some(e.to_string()),
                            }));
                        }
                    }
                }
                _ => {
                    warn!("⚠️ [PLATFORM_FEE] DKG key not available — cannot verify BTC balance");
                    return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                        status: "error".to_string(),
                        request_id: None,
                        amount: req.amount.clone(),
                        tics_target_address: req.tics_target_address.clone(),
                        btc_target_address: req.btc_target_address.clone(),
                        message: "Network not ready: DKG key not available".to_string(),
                        error_message: Some(
                            "Cannot derive BTC network address — DKG key generation not complete. Try again later."
                                .to_string(),
                        ),
                    }));
                }
            }
        };

        match crate::rpc_server::utils::fetch_network_balance(&network_address, blockchain).await {
            Ok(balance) => {
                if balance < requested_u128 {
                    warn!(
                        "❌ [PLATFORM_FEE] {} balance {} < requested {} amount {}",
                        liquidity_source, balance, asset, requested_u128
                    );
                    return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                        status: "error".to_string(),
                        request_id: None,
                        amount: req.amount.clone(),
                        tics_target_address: req.tics_target_address.clone(),
                        btc_target_address: req.btc_target_address.clone(),
                        message: format!("Insufficient {} balance", liquidity_source),
                        error_message: Some(format!(
                            "{} has {} but {} was requested. Fund it first.",
                            liquidity_source, balance, requested_u128
                        )),
                    }));
                }
                info!(
                    "✅ [PLATFORM_FEE] {} has sufficient balance: {} >= {}",
                    liquidity_source, balance, requested_u128
                );
            }
            Err(e) => {
                warn!(
                    "⚠️ [PLATFORM_FEE] Failed to fetch {} balance: {}",
                    liquidity_source, e
                );
                return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                    status: "error".to_string(),
                    request_id: None,
                    amount: req.amount.clone(),
                    tics_target_address: req.tics_target_address.clone(),
                    btc_target_address: req.btc_target_address.clone(),
                    message: format!("Failed to verify {} balance", liquidity_source),
                    error_message: Some(format!(
                        "Could not query {} balance: {e}",
                        liquidity_source
                    )),
                }));
            }
        }
    }

    // --- 5. One-claim-per-chain enforcement ---
    // Reject if there is already a Pending or Batched platform fee claim for the same asset.
    {
        let prefix = crate::database::primitives::keys::PENDING_CLAIM_PLATFORM_FEE;
        let entries: Vec<(String, PendingClaimPlatformFeeRequest)> =
            db.get_values_with_prefix(prefix).unwrap_or_default();
        let active = entries
            .iter()
            .find(|(_, r)| r.asset == asset && (r.status == "Pending" || r.status == "Batched"));
        if let Some((_, existing)) = active {
            warn!(
                "❌ [PLATFORM_FEE] Duplicate {} claim rejected — existing request_id={} is {}",
                asset, existing.request_id, existing.status
            );
            return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
                status: "error".to_string(),
                request_id: None,
                amount: req.amount.clone(),
                tics_target_address: req.tics_target_address.clone(),
                btc_target_address: req.btc_target_address.clone(),
                message: format!(
                    "A {} platform fee claim is already in progress (request_id={})",
                    asset, existing.request_id
                ),
                error_message: Some(format!(
                    "Existing {} request {} has status '{}' — only one per chain allowed",
                    asset, existing.request_id, existing.status
                )),
            }));
        }
    }

    // --- 6. Build the pending request record ---
    let request_id = format!("platform-fee-{}", uuid::Uuid::new_v4());

    let pending = PendingClaimPlatformFeeRequest {
        request_id: request_id.clone(),
        asset: asset.to_string(),
        amount: req.amount.clone(),
        tics_target_address: req.tics_target_address.clone(),
        btc_target_address: req.btc_target_address.clone(),
        message: req.message.clone(),
        // Carry the admin signature so every gossip recipient can independently
        // re-verify it matches ADMIN_PUBLIC_ADDRESS before storing in RocksDB.
        signature: req.signature.clone(),
        tx_id: None,
        status: "Pending".to_string(),
    };

    // --- 6. Broadcast to all nodes (local + peers) via channel ---
    let tx = message_tx.lock().await;
    if let Err(e) = tx
        .send(ChannelMessage::PendingClaimPlatformFeeRequestBroadcast {
            request: pending.clone(),
        })
        .await
    {
        warn!(
            "❌ [PLATFORM_FEE] Failed to enqueue broadcast for request_id={}: {}",
            request_id, e
        );
        return Ok(warp::reply::json(&ClaimPlatformFeeResponse {
            status: "error".to_string(),
            request_id: None,
            amount: req.amount.clone(),
            tics_target_address: req.tics_target_address.clone(),
            btc_target_address: req.btc_target_address.clone(),
            message: "Failed to submit platform fee claim to network".to_string(),
            error_message: Some(format!("Channel send error: {e}")),
        }));
    }

    info!(
        "✅ [PLATFORM_FEE] claim_platform_fee accepted: request_id={}, asset={}, amount={}",
        request_id, asset, req.amount
    );

    Ok(warp::reply::json(&ClaimPlatformFeeResponse {
        status: "pending".to_string(),
        request_id: Some(request_id),
        amount: req.amount,
        tics_target_address: req.tics_target_address,
        btc_target_address: req.btc_target_address,
        message: "Platform fee claim submitted — marked as pending across all nodes".to_string(),
        error_message: None,
    }))
}
