use std::{sync::Arc, time::Instant};

use tokio::sync::{mpsc, Mutex};
use tracing::info;
use warp::Filter;

use crate::{
    database::{DkgStorage, RewardStorage},
    types::ChannelMessage,
    user_registry::DatabaseUserRegistry,
};

use super::{
    handlers::{
        handle_claim_reward, handle_get_dkg_status, handle_get_node_id, handle_get_reward_solver,
        handle_get_status, handle_get_uptime, handle_get_user_info, handle_heartbeat,
        handle_register_user, handle_start_dkg, handle_user_mpc_deposit,
    },
    types::GetRewardSolverRequest,
};

pub async fn start_http_server(
    message_tx: mpsc::Sender<ChannelMessage>,
    port: u16,
    user_registry: Arc<DatabaseUserRegistry>,
    dkg_storage: DkgStorage,
    reward_storage: RewardStorage,
    node_id: String,
    start_time: Instant,
) -> Result<(), warp::Rejection> {
    info!(
        "🔗 [RPC_SERVER] Received user registry - Arc pointer: {:p}",
        Arc::as_ptr(&user_registry)
    );

    let message_tx = Arc::new(Mutex::new(message_tx));
    let dkg_storage = Arc::new(dkg_storage);
    let reward_storage = Arc::new(reward_storage);
    let start_time = Arc::new(start_time);

    let register_user = warp::path("register_user")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_user_registry(user_registry.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and(with_node_id(node_id.clone()))
        .and_then(handle_register_user);

    let user_mpc_deposit = warp::path("user_mpc_deposit")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_user_registry(user_registry.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and(with_dkg_storage(dkg_storage.clone()))
        .and_then(handle_user_mpc_deposit);

    let get_reward_solver = warp::path("get_reward_solver")
        .and(warp::get())
        .and(warp::query::<GetRewardSolverRequest>())
        .and(with_user_registry(user_registry.clone()))
        .and_then(handle_get_reward_solver);

    let claim_reward = warp::path("claim_reward")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_user_registry(user_registry.clone()))
        .and(with_reward_storage(reward_storage.clone()))
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_claim_reward);

    let get_user_info = warp::path("user_info")
        .and(warp::path::param())
        .and(warp::get())
        .and(with_user_registry(user_registry.clone()))
        .and_then(handle_get_user_info);

    let get_node_id = warp::path("node_id")
        .and(warp::get())
        .and(with_node_id(node_id.clone()))
        .and_then(handle_get_node_id);

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

    let start_dkg = warp::path("start_dkg")
        .and(warp::post())
        .and(with_message_tx(message_tx.clone()))
        .and_then(handle_start_dkg);

    let routes = register_user
        .or(get_user_info)
        .or(get_node_id)
        .or(get_status)
        .or(get_dkg_status)
        .or(start_dkg)
        .or(user_mpc_deposit)
        .or(get_reward_solver)
        .or(claim_reward)
        .or(heartbeat)
        .or(uptime);

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
            "Idempotency-Key",
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

    warp::serve(routes.with(cors))
        .run(([0, 0, 0, 0], port))
        .await;
    Ok(())
}

fn with_message_tx(
    message_tx: Arc<Mutex<mpsc::Sender<ChannelMessage>>>,
) -> impl Filter<
    Extract = (Arc<Mutex<mpsc::Sender<ChannelMessage>>>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || message_tx.clone())
}

fn with_user_registry(
    user_registry: Arc<DatabaseUserRegistry>,
) -> impl Filter<Extract = (Arc<DatabaseUserRegistry>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || user_registry.clone())
}

fn with_dkg_storage(
    dkg_storage: Arc<DkgStorage>,
) -> impl Filter<Extract = (Arc<DkgStorage>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || dkg_storage.clone())
}

fn with_reward_storage(
    reward_storage: Arc<RewardStorage>,
) -> impl Filter<Extract = (Arc<RewardStorage>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || reward_storage.clone())
}

fn with_node_id(
    node_id: String,
) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || node_id.clone())
}

fn with_start_time(
    start_time: Arc<Instant>,
) -> impl Filter<Extract = (Arc<Instant>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || start_time.clone())
}
