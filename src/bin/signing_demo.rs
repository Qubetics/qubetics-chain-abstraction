use libp2p::identity::Keypair;
use mpc_node::node_management::{
    DefaultThresholdCalculator, NodeMembership, ThresholdCalculator, VrfNodeManager,
};
use mpc_node::{
    commands::CommandProcessor, consensus::ConsensusNode, dkg::DKGNode, network::NetworkLayer,
    signing::SigningNode,
};
use rand::{thread_rng, Rng};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::info;
use tracing::{instrument::WithSubscriber, level_filters::LevelFilter};
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rand_num: u32 = thread_rng().gen_range(1000..9999);
    let file_appender =
        tracing_appender::rolling::never("logs", format!("signing-demo-{}.log", rand_num));
    let (writer, guard) = non_blocking(file_appender);
    let file_layer = fmt::layer::<_>()
        .with_writer(writer)
        .with_target(false)
        .with_level(true)
        .with_thread_ids(false)
        .with_thread_names(false);

    let stdout_layer = fmt::layer::<_>()
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_level(true)
        .with_thread_ids(false)
        .with_thread_names(false);

    let y = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse("")?;

    let _ = tracing_subscriber::registry()
        .with(y)
        .with(file_layer)
        .with(stdout_layer)
        .init();

    info!("🚀 Starting Signing Demo Node");

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

    let signing_node_clone = signing_node.clone();
    let mut dkg_node = DKGNode::new(
        network.get_local_peer_id().to_string(),
        threshold,
        total,
        network.get_msg_tx(),
    );

    // Set up DKG completion callback to provide secret share and group key to signing node
    dkg_node.set_completion_callback(Box::new(move |secret_share, group_key| {
        let signing_node = signing_node_clone.clone();
        tokio::spawn(async move {
            let mut signing_node = signing_node.lock().await;
            signing_node.set_secret_share(secret_share);
            signing_node.set_group_key(group_key);
            info!("🔗 [DEMO] DKG completion callback executed - signing node configured");
        });
    }));

    let consensus_node = ConsensusNode::new();
    let mut command_processor = CommandProcessor::new();

    // Register signing command handler
    let signing_node_cmd = signing_node.clone();
    command_processor.register_handler("sign_message".to_string(), move |cmd| {
        let signing_node = signing_node_cmd.clone();
        match cmd {
            mpc_node::commands::Command::SignMessage { message } => {
                info!("📝 [DEMO] Received sign message command: {:?}", message);
                tokio::spawn(async move {
                    let mut signing_node = signing_node.lock().await;
                    if let Err(e) = signing_node.sign_message(&message).await {
                        info!("❌ [DEMO] Failed to sign message: {:?}", e);
                    }
                });
                Ok(())
            }
            _ => Ok(()),
        }
    });

    network.set_dkg_node(dkg_node);
    network.set_signing_node(signing_node.lock().await.clone());
    network.set_consensus_node(consensus_node);
    network.set_command_processor(command_processor);

    // Start the network
    network.start().await?;

    // Wait a bit for network initialization
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Start DKG
    info!("🎯 [DEMO] Starting DKG process...");
    if let Some(dkg_node) = network.get_dkg_node() {
        if let Err(e) = dkg_node.start_dkg().await {
            info!("❌ [DEMO] Failed to start DKG: {:?}", e);
        }
    }

    // Wait for DKG to complete
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Check if DKG completed and trigger signing
    if let Some(dkg_node) = network.get_dkg_node() {
        if dkg_node.is_completed().await {
            info!("✅ [DEMO] DKG completed! Starting signing demo...");

            // Wait a bit more for all nodes to complete DKG
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Trigger message signing
            let test_message = b"Hello, this is a test message to be signed by the MPC network!";
            info!(
                "📝 [DEMO] Triggering signing of message: {:?}",
                test_message
            );

            let signing_node = signing_node.clone();
            tokio::spawn(async move {
                let mut signing_node = signing_node.lock().await;
                if let Err(e) = signing_node.sign_message(test_message).await {
                    info!("❌ [DEMO] Failed to sign message: {:?}", e);
                } else {
                    info!("✅ [DEMO] Signing process initiated successfully");
                }
            });
        } else {
            info!("⏳ [DEMO] DKG not yet completed, waiting...");
        }
    }

    // Keep the node running to observe signing process
    info!("🔄 [DEMO] Node running - observe logs for signing process...");
    tokio::time::sleep(Duration::from_secs(30)).await;

    info!("🏁 [DEMO] Signing demo completed");
    Ok(())
}
