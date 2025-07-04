use libp2p::identity::Keypair;
use mpc_node::node_management::{
    DefaultThresholdCalculator, NodeMembership, ThresholdCalculator, VrfNodeManager,
};
use mpc_node::{
    commands::CommandProcessor, consensus::ConsensusNode, dkg::DKGNode, network::NetworkLayer,
    rpc_server, signing::SigningNode,
};
use rand::{thread_rng, Rng};
#[allow(dead_code)]
#[allow(unused_imports)]
#[allow(non_snake_case)]
#[allow(unused_variables)]
use std::error::Error;
use std::fs::File;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing::{instrument::WithSubscriber, level_filters::LevelFilter};
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rand_num: u32 = thread_rng().gen_range(1000..9999);
    // let filename = format!("logs/mpcn-{}.log", rand_num);
    // let file_appender = rolling::daily("logs", "mpcn.log");
    // let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
    let file_appender = tracing_appender::rolling::never("logs", format!("mpcn-{}.log", rand_num));
    // let file = File::create(&filename).expect("Failed to create log file");
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
    let stderr_layer = fmt::layer::<_>()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_level(true)
        .with_thread_ids(false)
        .with_thread_names(false);

    let x = EnvFilter::new("info");
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
            info!("🔗 [MAIN] DKG completion callback executed - signing node configured");
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
                info!("📝 [MAIN] Received sign message command: {:?}", message);
                tokio::spawn(async move {
                    let mut signing_node = signing_node.lock().await;
                    if let Err(e) = signing_node.sign_message(&message).await {
                        info!("❌ [MAIN] Failed to sign message: {:?}", e);
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

    // Start RPC server in a separate task
    let message_tx = network.get_msg_tx();
    let rpc_port = 8080; // You can make this configurable

    tokio::spawn(async move {
        info!("🚀 Starting RPC server on port {}", rpc_port);
        if let Err(e) = rpc_server::start_http_server(message_tx, rpc_port).await {
            info!("❌ RPC server failed: {:?}", e);
        }
    });

    // Start the network
    network.start().await?;

    Ok(())
}

#[cfg(test)]
mod test {
    use tracing_subscriber::fmt::format;

    fn call_once<F>(f: F)
    where
        F: FnOnce(),
    {
        f();
    }

    fn call_borrow<F>(f: F)
    where
        F: Fn(),
    {
        f();
        f();
    }

    fn call_borrow_mut<F: FnMut()>(mut f: F) {
        f();
        f();
    }

    #[test]
    fn test_it() {
        let mut ct = 100;
        let mut s = String::from("value");
        let inc = || {
            ct += 1;
            let a = ct;
        };
        call_borrow_mut(inc);
        assert_eq!(ct, 102);
        let inc = || println!("ct {}", ct);
        call_borrow(inc);
        assert_eq!(ct, 102);
        let inc = move || {
            for i in 0..10 {
                println!("{s}");
            }
        };
        call_borrow(inc);
        assert_eq!(ct, 102);
    }
}
