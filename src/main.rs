use dotenv::dotenv;
use libp2p::identity::Keypair;
use mpc_node::node_management::{DefaultThresholdCalculator, NodeMembership, VrfNodeManager};
use mpc_node::{
    adkg_secp256k1::DKGNode,
    commands::CommandProcessor,
    consensus::{ConsensusNode, DatabaseConsensusNode},
    database::{Database, DatabaseConfig, DkgStorage, RewardStorage},
    network::NetworkLayer,
    rpc_server,
    signing::{DatabaseSigningNode, SigningNode},
    user_registry::DatabaseUserRegistry,
};
use rand::{thread_rng, Rng};
#[allow(dead_code)]
#[allow(unused_imports)]
#[allow(non_snake_case)]
#[allow(unused_variables)]
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load environment variables from .env file
    dotenv().ok();

    let node_start_time = Instant::now();
    let rand_num: u32 = thread_rng().gen_range(1000..9999);
    let file_appender = tracing_appender::rolling::never("logs", format!("mpcn-{}.log", rand_num));
    let (writer, _guard) = non_blocking(file_appender);
    let file_layer = fmt::layer::<_>()
        .with_writer(writer)
        .with_target(true)
        .with_level(true)
        .with_thread_ids(false)
        .with_thread_names(false);

    let stdout_layer = fmt::layer::<_>()
        .with_writer(std::io::stdout)
        .with_target(true)
        .with_level(true)
        .with_thread_ids(false)
        .with_thread_names(false);
    let stderr_layer = fmt::layer::<_>()
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_level(true)
        .with_thread_ids(false)
        .with_thread_names(false);

    // let x = EnvFilter::new("info");
    let y = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse("")?;

    let _ = tracing_subscriber::registry()
        .with(y)
        .with(file_layer)
        .with(stdout_layer)
        .with(stderr_layer)
        .init();

    // Generate node identity
    let local_key = Keypair::generate_ed25519();
    let local_peer_id = libp2p::PeerId::from(local_key.public());

    // Create VRF-based node manager
    let threshold_calculator = Box::new(DefaultThresholdCalculator);
    let node_manager = Box::new(VrfNodeManager::new(
        local_peer_id,
        threshold_calculator,
        10, // selection interval
    ));

    let total = node_manager.get_total_nodes();
    let threshold = node_manager.get_threshold();

    info!("Initial node count: {}, threshold: {}", total, threshold);

    // Initialize database
    let db_config = DatabaseConfig {
        path: format!(
            "./data/rocksdb-{}",
            local_peer_id
                .to_string()
                .chars()
                .take(8)
                .collect::<String>()
        ),
        create_if_missing: true,
        max_open_files: 1000,
    };
    let database = Arc::new(Database::new(db_config)?);
    info!("🗄️ [MAIN] Database initialized successfully");

    let mut network = NetworkLayer::new(node_manager).await?;

    // Create database-backed components
    let db_signing_node = Arc::new(Mutex::new(DatabaseSigningNode::new(
        network.get_local_peer_id().to_string(),
        threshold,
        network.get_msg_tx(),
        database.as_ref().clone(),
    )));

    // Create legacy signing node for compatibility (can be removed later)
    let signing_node = Arc::new(Mutex::new(SigningNode::new(
        network.get_local_peer_id().to_string(),
        threshold,
        network.get_msg_tx(),
    )));

    let dkg_storage = DkgStorage::new(database.as_ref().clone());
    let reward_storage = RewardStorage::new(database.as_ref().clone());
    let chain_code = [42u8; 32]; // Placeholder chain code
    let dkg_node = DKGNode::new(
        network.get_local_peer_id().to_string(),
        threshold,
        total,
        network.get_msg_tx(),
        dkg_storage.clone(),
        chain_code,
    );

    let db_consensus_node = DatabaseConsensusNode::new(database.as_ref().clone());
    let consensus_node = ConsensusNode::new(); // Keep legacy for compatibility
    let command_processor = CommandProcessor::new();

    network.set_dkg_node(dkg_node);
    network.set_signing_node(signing_node.lock().await.clone());
    network.set_db_signing_node(db_signing_node.clone());
    network.set_consensus_node(consensus_node);
    network.set_command_processor(command_processor);

    // Create database-backed user registry
    let db_user_registry = Arc::new(DatabaseUserRegistry::new(
        database.as_ref().clone(),
        chain_code,
    ));
    info!("🏗️ [MAIN] Created Arc<DatabaseUserRegistry>");

    // Legacy user registry removed - now using database-backed registry

    // Set database user registry in network layer (this will also set it on the signing node)
    info!(
        "🔗 [MAIN] Setting database user registry in network layer - Arc pointer: {:p}",
        Arc::as_ptr(&db_user_registry)
    );
    network.set_user_registry(db_user_registry.clone());

    // Set database on signing node for solver amount storage
    network.set_database(database);

    // Start RPC server in a separate task
    let message_tx = network.get_msg_tx();
    let rpc_port = std::env::var("RPC_PORT")
        .unwrap_or_else(|_| "8081".to_string())
        .parse::<u16>()
        .unwrap_or(8081);
    let node_id = network.get_local_peer_id().to_string();

    let start_time = node_start_time;
    tokio::spawn(async move {
        info!("🚀 Starting RPC server on port {}", rpc_port);
        info!(
            "🔗 [MAIN] Passing database user registry to RPC server - Arc pointer: {:p}",
            Arc::as_ptr(&db_user_registry)
        );
        if let Err(e) = rpc_server::start_http_server(
            message_tx,
            rpc_port,
            db_user_registry.clone(),
            dkg_storage,
            reward_storage,
            node_id,
            start_time,
        )
        .await
        {
            info!("❌ RPC server failed: {:?}", e);
        }
    });

    // Log database components availability
    info!("📊 [MAIN] Database components initialized:");
    info!("  📝 DatabaseSigningNode: Available");
    info!("  🗳️ DatabaseConsensusNode: Available");
    info!("  👥 DatabaseUserRegistry: Available");
    info!(
        "  🗄️ Database path: {}",
        format!(
            "./data/rocksdb-{}",
            local_peer_id
                .to_string()
                .chars()
                .take(8)
                .collect::<String>()
        )
    );

    // Start the network
    network.start().await?;

    Ok(())
}
