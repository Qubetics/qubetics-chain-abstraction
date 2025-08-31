use libp2p::identity::Keypair;
use mpc_node::node_management::{DefaultThresholdCalculator, NodeMembership, VrfNodeManager};
use mpc_node::{
    adkg_secp256k1::DKGNode, commands::CommandProcessor, consensus::ConsensusNode,
    network::NetworkLayer, rpc_server, signing::SigningNode, user_registry::UserRegistry,
};
use rand::{thread_rng, Rng};
#[allow(dead_code)]
#[allow(unused_imports)]
#[allow(non_snake_case)]
#[allow(unused_variables)]
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

    let mut network = NetworkLayer::new(node_manager).await?;

    let signing_node = Arc::new(Mutex::new(SigningNode::new(
        network.get_local_peer_id().to_string(),
        threshold,
        network.get_msg_tx(),
    )));

    // let signing_node_clone = signing_node.clone();
    let dkg_node = DKGNode::new(
        network.get_local_peer_id().to_string(),
        threshold,
        total,
        network.get_msg_tx(),
    );

    let consensus_node = ConsensusNode::new();
    let command_processor = CommandProcessor::new();

    network.set_dkg_node(dkg_node);
    network.set_signing_node(signing_node.lock().await.clone());
    network.set_consensus_node(consensus_node);
    network.set_command_processor(command_processor);

    // Create user registry with a default chain code
    // TODO: Replace with actual chain code from DKG or secure source
    let chain_code = [42u8; 32]; // Placeholder chain code
    let user_registry = UserRegistry::new(chain_code);

    // Set user registry in network layer
    network.set_user_registry(user_registry.clone());

    // Create shared state for DKG secret share access
    let dkg_shared_state = Arc::new(RwLock::new(rpc_server::DKGSharedState::new()));

    // Set up DKG completion callback to update shared state
    let dkg_shared_state_clone = dkg_shared_state.clone();
    if let Some(dkg_node) = network.get_dkg_node() {
        // Set completion callback to update shared state when DKG completes
        dkg_node.set_completion_callback(Box::new(move |secret_share, _public_key| {
            let dkg_state = dkg_shared_state_clone.clone();
            // Use tokio::spawn to handle the async operation
            tokio::spawn(async move {
                let mut state = dkg_state.write().await;
                state.set_secret_share(secret_share);
                info!("🔐 DKG completion callback: Secret share stored in shared state");
            });
        }));
    }

    // Start RPC server in a separate task
    let message_tx = network.get_msg_tx();
    let rpc_port = 8081; // You can make this configurable
    let node_id = network.get_local_peer_id().to_string();

    // Create user registry with a default chain code
    // TODO: Replace with actual chain code from DKG or secure source
    let chain_code = [42u8; 32]; // Placeholder chain code
    let user_registry = UserRegistry::new(chain_code);

    // Set user registry in network layer
    network.set_user_registry(user_registry.clone());

    tokio::spawn(async move {
        info!("🚀 Starting RPC server on port {}", rpc_port);
        if let Err(e) = rpc_server::start_http_server(message_tx, rpc_port, user_registry, dkg_shared_state, node_id).await {
            info!("❌ RPC server failed: {:?}", e);
        }
    });

    // Start the network
    network.start().await?;

    Ok(())
}
