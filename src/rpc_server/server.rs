use std::{convert::Infallible, sync::Arc, time::Instant};

use serde::de::DeserializeOwned;
use tokio::{
    sync::{mpsc, Mutex},
    time::Duration,
};
use tracing::{error, info};
use warp::{Filter, Reply};

use crate::{
    database::{Database, DkgStorage},
    types::ChannelMessage,
    user_intent_manager::UserIntentManager,
};

use super::{
    errors::RpcError,
    handlers::{
        handle_add_liquidity, handle_check_peer_connection, handle_claim_reward,
        handle_get_dkg_status, handle_get_intent_details, handle_get_intents_solved_count,
        handle_get_network_addresses, handle_get_node_id, handle_get_pending_intents_count,
        handle_get_node_info, handle_get_solver_liquidity, handle_get_solver_rewards,
        handle_get_status, handle_get_uptime, handle_get_user_count, handle_get_user_info,
        handle_heartbeat, handle_log_partial_pubkeys, handle_register_user, handle_rejoin_status,
        handle_user_mpc_deposit, handle_withdraw_liquidity,
    },
    rate_limiter::RateLimiter,
    upgrade_handlers::{
        handle_cleanup_snapshots, handle_complete_upgrade, handle_rollback, handle_upgrade,
        handle_upgrade_status, handle_validate_upgrade, CleanupSnapshotsRequest, RollbackRequest,
        StartUpgradeRequest as UpgradeRequest, ValidateUpgradeRequest,
    },
};
use crate::types::rpc_server::{
    AddLiquidityRequest, ClaimRewardRequest, GetSolverRewardsRequest, RequestContext,
    SolverLiquidityRequest, UserMpcDepositRequest, UserMpcDepositVerifyResponse,
    UserRegistrationRequest, WithdrawLiquidityRequest,
};

const MAX_REQUEST_BODY_BYTES: u64 = 256 * 1024; // 256 KiB
const REQUEST_TIMEOUT_SECONDS: u64 = 900;
// Rate limiting configuration
// Per-IP: 10 requests per 60 seconds
const RATE_LIMIT_MAX_REQUESTS_PER_IP: u32 = 10;
// Global: 100 requests (all IPs combined) per 60 seconds
const RATE_LIMIT_MAX_GLOBAL_REQUESTS: u32 = 100;
const RATE_LIMIT_WINDOW_SECONDS: u64 = 60; // Time window in seconds

pub async fn start_http_server(
    message_tx: mpsc::Sender<ChannelMessage>,
    port: u16,
    user_intent_manager: Arc<UserIntentManager>,
    dkg_storage: DkgStorage,
    database: Database,
    node_id: String,
    start_time: Instant,
) -> Result<(), warp::Rejection> {
    info!(
        "🔗 [RPC_SERVER] Received user registry - Arc pointer: {:p}",
        Arc::as_ptr(&user_intent_manager)
    );

    let message_tx = Arc::new(Mutex::new(message_tx));
    let dkg_storage = Arc::new(dkg_storage);
    let database = Arc::new(database);
    let start_time = Arc::new(start_time);

    // Initialize rate limiters
    let ip_rate_limiter = Arc::new(RateLimiter::new(
        RATE_LIMIT_MAX_REQUESTS_PER_IP,
        Duration::from_secs(RATE_LIMIT_WINDOW_SECONDS),
    ));
    let global_rate_limiter = Arc::new(RateLimiter::new(
        RATE_LIMIT_MAX_GLOBAL_REQUESTS,
        Duration::from_secs(RATE_LIMIT_WINDOW_SECONDS),
    ));

    // Start background cleanup task for per-IP rate limiter
    let ip_rate_limiter_cleanup = ip_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Cleanup every 5 minutes
        loop {
            interval.tick().await;
            ip_rate_limiter_cleanup.cleanup().await;
        }
    });

    // Start background cleanup task for global rate limiter
    let global_rate_limiter_cleanup = global_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Cleanup every 5 minutes
        loop {
            interval.tick().await;
            global_rate_limiter_cleanup.cleanup().await;
        }
    });

    info!(
        "🚦 [RATE_LIMIT] Rate limiter initialized: {} requests/IP and {} requests total per {} seconds",
        RATE_LIMIT_MAX_REQUESTS_PER_IP,
        RATE_LIMIT_MAX_GLOBAL_REQUESTS,
        RATE_LIMIT_WINDOW_SECONDS
    );

    let json_body_user_registration = limited_json_body::<UserRegistrationRequest>();
    let register_user = warp::path("register_user")
        .and(warp::post())
        .and(with_rate_limit(
            ip_rate_limiter.clone(),
            global_rate_limiter.clone(),
        ))
        .and(json_body_user_registration)
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and(with_node_id(node_id.clone()))
        .and(with_auth())
        .and_then(handle_register_user);

    let user_mpc_deposit = warp::path("user_mpc_deposit")
        .and(warp::post())
        .and(with_rate_limit(
            ip_rate_limiter.clone(),
            global_rate_limiter.clone(),
        ))
        .and(limited_json_body::<UserMpcDepositRequest>())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and(with_request_context())
        .and(with_auth())
        .and_then(|req, uim, tx, dkg, ctx: RequestContext| async move {
            match tokio::time::timeout(
                Duration::from_secs(REQUEST_TIMEOUT_SECONDS),
                handle_user_mpc_deposit(req, uim, tx, dkg, ctx.clone()),
            )
            .await
            {
                Ok(res) => res.map(|reply| reply.into_response()),
                Err(_) => {
                    error!(
                        request_id = %ctx.request_id,
                        "❌ user_mpc_deposit handler timed out"
                    );
                    let timeout_reply = warp::reply::with_status(
                        warp::reply::json(&UserMpcDepositVerifyResponse {
                            status: "timeout".to_string(),
                            intent_hash: "".to_string(),
                            error_message: Some(
                                "Request timed out before processing could complete".to_string(),
                            ),
                            signer_eth_address: None,
                        }),
                        warp::http::StatusCode::REQUEST_TIMEOUT,
                    );
                    Ok(timeout_reply.into_response())
                }
            }
        });

    let get_solver_liquidity = warp::path("solver_liquidity")
        .and(warp::get())
        .and(warp::query::<SolverLiquidityRequest>())
        .and_then(handle_get_solver_liquidity);

    let get_solver_rewards = warp::path("solver_rewards")
        .and(warp::get())
        .and(warp::query::<GetSolverRewardsRequest>())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and_then(handle_get_solver_rewards);

    let claim_reward = warp::path("claim_reward")
        .and(warp::post())
        .and(with_rate_limit(
            ip_rate_limiter.clone(),
            global_rate_limiter.clone(),
        ))
        .and(limited_json_body::<ClaimRewardRequest>())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and(with_auth())
        .and_then(handle_claim_reward);

    let add_liquidity = warp::path("solver_add_liquidity")
        .and(warp::post())
        .and(with_rate_limit(
            ip_rate_limiter.clone(),
            global_rate_limiter.clone(),
        ))
        .and(limited_json_body::<AddLiquidityRequest>())
        .and(with_message_tx(message_tx.clone()))
        .and(with_auth())
        .and_then(handle_add_liquidity);

    let withdraw_liquidity = warp::path("withdraw_liquidity")
        .and(warp::post())
        .and(with_rate_limit(
            ip_rate_limiter.clone(),
            global_rate_limiter.clone(),
        ))
        .and(limited_json_body::<WithdrawLiquidityRequest>())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and(with_auth())
        .and_then(handle_withdraw_liquidity);

    let get_user_info = warp::path("user_info")
        .and(warp::path::param())
        .and(warp::get())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and_then(handle_get_user_info);

    let get_intent_details = warp::path("intent_details")
        .and(warp::path::param())
        .and(warp::get())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and_then(handle_get_intent_details);

    let get_node_id = warp::path("node_id")
        .and(warp::get())
        .and(with_node_id(node_id.clone()))
        .and_then(handle_get_node_id);

    let get_node_info = warp::path("node-info")
        .and(warp::get())
        .and(with_dkg_storage(dkg_storage.clone()))
        .and(with_node_id(node_id.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_get_node_info);

    let get_status = warp::path("status")
        .and(warp::get())
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_get_status);

    let get_dkg_status = warp::path("dkg_status")
        .and(warp::get())
        .and(with_dkg_storage(dkg_storage.clone()))
        .and_then(handle_get_dkg_status);

    let heartbeat = warp::path("heartbeat")
        .and(warp::get())
        .and_then(handle_heartbeat);

    let uptime = warp::path("uptime")
        .and(warp::get())
        .and(with_start_time(start_time.clone()))
        .and_then(handle_get_uptime);

    let log_partial_pubkeys = warp::path("log_partial_pubkeys")
        .and(warp::post())
        .and(with_rate_limit(
            ip_rate_limiter.clone(),
            global_rate_limiter.clone(),
        ))
        .and(limited_json_body::<
            crate::types::rpc_server::LogPartialPubkeysRequest,
        >())
        .and(with_dkg_storage(dkg_storage.clone()))
        .and_then(handle_log_partial_pubkeys);

    let get_network_addresses = warp::path("get_network_addresses")
        .and(warp::get())
        .and(with_dkg_storage(dkg_storage.clone()))
        .and_then(handle_get_network_addresses);

    let get_intents_solved_count = warp::path("intents_solved_count")
        .and(warp::get())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and_then(handle_get_intents_solved_count);

    let get_pending_intents_count = warp::path("pending_intents_count")
        .and(warp::get())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and_then(handle_get_pending_intents_count);

    let get_user_count = warp::path("user_count")
        .and(warp::get())
        .and(with_user_intent_manager(user_intent_manager.clone()))
        .and_then(handle_get_user_count);

    let rejoin_status = warp::path("rejoin-status")
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(with_database(database.clone()))
        .and_then(handle_rejoin_status);

    let check_peer_connection = warp::path("check-peer-connection")
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_check_peer_connection);

    // Upgrade endpoints
    let validate_upgrade = warp::path("validate-upgrade")
        .and(warp::post())
        .and(limited_json_body::<ValidateUpgradeRequest>())
        .and(with_database(database.clone()))
        .and(with_node_id(node_id.clone()))
        .and(with_auth())
        .and_then(handle_validate_upgrade);

    let upgrade = warp::path("upgrade")
        .and(warp::post())
        .and(limited_json_body::<UpgradeRequest>())
        .and(with_database(database.clone()))
        .and(with_node_id(node_id.clone()))
        .and(with_auth())
        .and_then(handle_upgrade);

    let upgrade_status = warp::path("upgrade-status")
        .and(warp::get())
        .and(with_database(database.clone()))
        .and_then(handle_upgrade_status);

    let rollback = warp::path("rollback")
        .and(warp::post())
        .and(limited_json_body::<RollbackRequest>())
        .and(with_database(database.clone()))
        .and(with_auth())
        .and_then(handle_rollback);

    let cleanup_snapshots = warp::path("cleanup-snapshots")
        .and(warp::post())
        .and(limited_json_body::<CleanupSnapshotsRequest>())
        .and(with_database(database.clone()))
        .and(with_auth())
        .and_then(handle_cleanup_snapshots);

    let complete_upgrade = warp::path("complete-upgrade")
        .and(warp::post())
        .and(with_database(database.clone()))
        .and(with_auth())
        .and_then(handle_complete_upgrade);

    let routes = register_user
        .or(get_user_info)
        .or(get_intent_details)
        .or(get_node_id)
        .or(get_node_info)
        .or(get_status)
        .or(get_dkg_status)
        .or(user_mpc_deposit)
        .or(get_solver_liquidity)
        .or(get_solver_rewards)
        .or(claim_reward)
        .or(add_liquidity)
        .or(withdraw_liquidity)
        .or(heartbeat)
        .or(uptime)
        .or(log_partial_pubkeys)
        .or(get_network_addresses)
        .or(get_intents_solved_count)
        .or(get_pending_intents_count)
        .or(get_user_count)
        .or(rejoin_status)
        .or(check_peer_connection)
        .or(validate_upgrade)
        .or(upgrade)
        .or(upgrade_status)
        .or(rollback)
        .or(cleanup_snapshots)
        .or(complete_upgrade);

    info!("🌐 Starting HTTP RPC server on port {}", port);
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        .allow_headers(vec![
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Origin",
            "Authorization",
            "X-Api-Key",
            "X-Auth-Token",
            "X-Auth-Token",
            "X-Requested-With",
            "X-CSRF-Token",
            "Cache-Control",
            "Pragma",
            "If-None-Match",
            "If-Match",
            "If-Modified-Since",
            "If-Unmodified-Since",
            "Range",
            "Content-Range",
            "X-Client-Id",
            "X-Client-Version",
            "X-Device-Id",
            "X-Platform",
            "X-Session-Id",
            "X-Trace-Id",
            "X-Request-Id",
            "X-Signature",
            "X-Signature-Version",
            "X-Timestamp",
            "X-Nonce",
            "X-HTTP-Method-Override",
            "X-Requested-By",
        ]);

    warp::serve(routes.with(cors).recover(handle_rejection))
        .run(([0, 0, 0, 0], port))
        .await;
    Ok(())
}

async fn handle_rejection(err: warp::Rejection) -> Result<impl Reply, Infallible> {
    let (code, response) = if err.is_not_found() {
        (
            warp::http::StatusCode::NOT_FOUND,
            crate::types::rpc_server::ErrorResponse {
                status: "error".to_string(),
                error_code: "NOT_FOUND".to_string(),
                message: "Not Found".to_string(),
                details: None,
            },
        )
    } else if let Some(e) = err.find::<super::errors::RpcError>() {
        let code = match e {
            super::errors::RpcError::Unauthorized(_) => warp::http::StatusCode::UNAUTHORIZED,
            super::errors::RpcError::RateLimitExceeded(_) => {
                warp::http::StatusCode::TOO_MANY_REQUESTS
            }
            super::errors::RpcError::InternalError(_) => {
                warp::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => warp::http::StatusCode::BAD_REQUEST,
        };
        (code, e.to_error_response())
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        (
            warp::http::StatusCode::METHOD_NOT_ALLOWED,
            crate::types::rpc_server::ErrorResponse {
                status: "error".to_string(),
                error_code: "METHOD_NOT_ALLOWED".to_string(),
                message: "Method Not Allowed".to_string(),
                details: None,
            },
        )
    } else {
        error!("Unhandled rejection: {:?}", err);
        (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            crate::types::rpc_server::ErrorResponse {
                status: "error".to_string(),
                error_code: "INTERNAL_SERVER_ERROR".to_string(),
                message: "Internal Server Error".to_string(),
                details: Some(format!("{:?}", err)),
            },
        )
    };

    Ok(warp::reply::with_status(warp::reply::json(&response), code))
}

fn limited_json_body<T>() -> impl Filter<Extract = (T,), Error = warp::Rejection> + Clone
where
    T: DeserializeOwned + Send,
{
    warp::body::content_length_limit(MAX_REQUEST_BODY_BYTES)
        .and(warp::body::json::<T>())
        .map(|body: T| body)
}

fn with_message_tx(
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> impl Filter<Extract = (Arc<Mutex<mpsc::Sender<ChannelMessage>>>,), Error = Infallible> + Clone
{
    warp::any().map(move || message_tx.clone())
}

fn with_user_intent_manager(
    user_intent_manager: Arc<UserIntentManager>,
) -> impl Filter<Extract = (Arc<UserIntentManager>,), Error = Infallible> + Clone {
    warp::any().map(move || user_intent_manager.clone())
}

fn with_dkg_storage(
    dkg_storage: Arc<DkgStorage>,
) -> impl Filter<Extract = (Arc<DkgStorage>,), Error = Infallible> + Clone {
    warp::any().map(move || dkg_storage.clone())
}

fn with_database(
    database: Arc<Database>,
) -> impl Filter<Extract = (Arc<Database>,), Error = Infallible> + Clone {
    warp::any().map(move || database.clone())
}

fn with_node_id(node_id: String) -> impl Filter<Extract = (String,), Error = Infallible> + Clone {
    warp::any().map(move || node_id.clone())
}

fn with_start_time(
    start_time: Arc<Instant>,
) -> impl Filter<Extract = (Arc<Instant>,), Error = Infallible> + Clone {
    warp::any().map(move || start_time.clone())
}

fn with_request_context() -> impl Filter<Extract = (RequestContext,), Error = Infallible> + Clone {
    warp::any().map(|| RequestContext::new())
}

fn with_auth() -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("X-API-KEY")
        .and_then(|api_key: Option<String>| async move {
            let expected_key =
                std::env::var("RPC_API_KEY").unwrap_or_else(|_| "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45".to_string());
            info!(
                "🔐 Auth Check: Received '{:?}', Expected '{}'",
                api_key, expected_key
            );
            match api_key {
                Some(key) if key == expected_key => Ok(()),
                _ => Err(warp::reject::custom(super::errors::RpcError::Unauthorized(
                    "Invalid or missing API key".to_string(),
                ))),
            }
        })
        .untuple_one()
}

fn with_rate_limit(
    ip_rate_limiter: Arc<RateLimiter>,
    global_rate_limiter: Arc<RateLimiter>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::addr::remote()
        .and_then(move |addr: Option<std::net::SocketAddr>| {
            let ip_rate_limiter = ip_rate_limiter.clone();
            let global_rate_limiter = global_rate_limiter.clone();
            async move {
                let ip = addr
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                // Per-IP limit
                if !ip_rate_limiter.check(&ip).await {
                    return Err(warp::reject::custom(RpcError::RateLimitExceeded(format!(
                        "Rate limit exceeded for IP: {}. Maximum {} requests per {} seconds allowed.",
                        ip, RATE_LIMIT_MAX_REQUESTS_PER_IP, RATE_LIMIT_WINDOW_SECONDS
                    ))));
                }

                // Global limit (all IPs combined)
                if !global_rate_limiter.check("GLOBAL").await {
                    return Err(warp::reject::custom(RpcError::RateLimitExceeded(format!(
                        "Global rate limit exceeded. Maximum {} requests per {} seconds allowed.",
                        RATE_LIMIT_MAX_GLOBAL_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
                    ))));
                }

                Ok(())
            }
        })
        .untuple_one()
}
