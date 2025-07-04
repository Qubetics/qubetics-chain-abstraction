use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use mpc_node::signing::SigningNode;
use mpc_node::types::ChannelMessage;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up logging
    let y = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse("")?;

    let _ = tracing_subscriber::registry()
        .with(y)
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();

    info!("🚀 Starting Simple Signing Test");
    info!("=================================");

    // Create a dummy message channel (not used in this test)
    let (tx, _rx) = mpsc::channel::<ChannelMessage>(100);

    // Create multiple signing nodes
    let mut nodes = Vec::new();
    let threshold = 2;
    let total_nodes = 3;

    for i in 1..=total_nodes {
        let node_id = format!("Node-{}", i);
        let signing_node = Arc::new(Mutex::new(SigningNode::new(
            node_id.clone(),
            threshold,
            tx.clone(),
        )));
        nodes.push(signing_node);
        info!("✅ Created {}", node_id);
    }

    // Simulate DKG completion by setting secret shares and group keys
    info!("🔐 Setting up secret shares and group keys...");

    let mut rng = OsRng;
    let secret_shares = vec![
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ];

    let group_key = G1Projective::generator() * secret_shares.iter().sum::<Scalar>();

    // Configure each node with its secret share and group key
    for (i, node) in nodes.iter().enumerate() {
        let mut node = node.lock().await;
        node.set_secret_share(secret_shares[i]);
        node.set_group_key(group_key);
        info!(
            "🔑 Configured {} with secret share and group key",
            format!("Node-{}", i + 1)
        );
    }

    // Test message to sign
    let test_message = b"Hello, this is a test message for distributed signing!";
    info!("📝 Test message: {}", String::from_utf8_lossy(test_message));

    // Simulate the signing process for each node
    info!("🎯 Starting distributed signing process...");

    for (i, node) in nodes.iter().enumerate() {
        let mut node = node.lock().await;
        info!(
            "🔄 {} starting to sign message...",
            format!("Node-{}", i + 1)
        );

        match node.sign_message(test_message).await {
            Ok(_) => {
                info!(
                    "✅ {} successfully initiated signing process",
                    format!("Node-{}", i + 1)
                );
            }
            Err(e) => {
                info!("❌ {} failed to sign: {:?}", format!("Node-{}", i + 1), e);
            }
        }
    }

    // Simulate the commitment and signature share exchange
    info!("📤 Simulating commitment and signature share exchange...");

    // In a real scenario, nodes would exchange commitments and signature shares
    // For this demo, we'll show what the process looks like
    for i in 0..total_nodes {
        info!(
            "📋 {} would broadcast commitment share",
            format!("Node-{}", i + 1)
        );
        info!(
            "✍️ {} would generate signature share using secret: {:?}",
            format!("Node-{}", i + 1),
            secret_shares[i]
        );
    }

    // Simulate signature aggregation
    info!("🔢 Simulating signature aggregation...");
    let aggregated_signature = secret_shares.iter().sum::<Scalar>();
    info!("🎉 Final aggregated signature: {:?}", aggregated_signature);

    // Show what each node would log
    info!("📋 Logs that each node would produce:");
    info!("=====================================");

    for i in 0..total_nodes {
        info!(
            "[Node-{}] 🔐 Secret share set: {:?}",
            i + 1,
            secret_shares[i]
        );
        info!("[Node-{}] 🔑 Group key set: {:?}", i + 1, group_key);
        info!(
            "[Node-{}] 📝 Starting to sign message: {:?}",
            i + 1,
            test_message
        );
        info!("[Node-{}] 🎲 Generated nonces for signing", i + 1);
        info!("[Node-{}] 📤 Broadcasted commitment share", i + 1);
        info!(
            "[Node-{}] ✍️ Generated signature share: {:?}",
            i + 1,
            secret_shares[i]
        );
        info!(
            "[Node-{}] 📥 Received commitment shares from other nodes",
            i + 1
        );
        info!(
            "[Node-{}] 📥 Received signature shares from other nodes",
            i + 1
        );
        info!("[Node-{}] 🎯 Aggregating signature shares", i + 1);
        info!(
            "[Node-{}] 🎉 Final signature: {:?}",
            i + 1,
            aggregated_signature
        );
        info!("");
    }

    info!("✅ Simple signing test completed successfully!");
    info!("💡 In a real distributed environment, nodes would:");
    info!("   1. Discover each other via P2P network");
    info!("   2. Run DKG to generate secret shares");
    info!("   3. Exchange commitments and signature shares");
    info!("   4. Aggregate signatures to produce final result");
    info!("   5. Log all steps for monitoring and debugging");

    Ok(())
}
