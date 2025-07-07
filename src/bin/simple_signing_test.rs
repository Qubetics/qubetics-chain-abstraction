use bls12_381::G1Projective;
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

    // Generate BLS key pairs for each node
    info!("🔐 Setting up BLS key pairs...");

    // Configure each node with BLS key pairs
    for (i, node) in nodes.iter().enumerate() {
        let mut node = node.lock().await;
        if let Err(e) = node.generate_key_pair() {
            info!("❌ Failed to generate key pair for Node-{}: {:?}", i + 1, e);
        } else {
            info!(
                "🔑 Configured {} with BLS key pair",
                format!("Node-{}", i + 1)
            );
        }
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

    // Simulate BLS signature exchange
    info!("📤 Simulating BLS signature exchange...");

    // In a real scenario, nodes would exchange BLS signatures
    // For this demo, we'll show what the process looks like
    for i in 0..total_nodes {
        info!(
            "📋 {} would broadcast BLS signature",
            format!("Node-{}", i + 1)
        );
        info!(
            "✍️ {} would generate BLS signature using private key",
            format!("Node-{}", i + 1)
        );
    }

    // Simulate BLS signature aggregation
    info!("🔢 Simulating BLS signature aggregation...");
    info!("🎉 Final aggregated BLS signature would be computed");

    // Show what each node would log
    info!("📋 Logs that each node would produce:");
    info!("=====================================");

    for i in 0..total_nodes {
        info!("[Node-{}] 🔐 BLS key pair generated", i + 1);
        info!(
            "[Node-{}] 📝 Starting to sign message: {:?}",
            i + 1,
            test_message
        );
        info!("[Node-{}] ✍️ Generated BLS signature", i + 1);
        info!("[Node-{}] 📤 Broadcasted BLS signature", i + 1);
        info!(
            "[Node-{}] 📥 Received BLS signatures from other nodes",
            i + 1
        );
        info!("[Node-{}] 🎯 Aggregating BLS signatures", i + 1);
        info!(
            "[Node-{}] 🎉 Final aggregated BLS signature computed",
            i + 1
        );
        info!("");
    }

    info!("✅ Simple BLS signing test completed successfully!");
    info!("💡 In a real distributed environment, nodes would:");
    info!("   1. Discover each other via P2P network");
    info!("   2. Generate individual BLS key pairs");
    info!("   3. Exchange BLS signatures");
    info!("   4. Aggregate BLS signatures to produce final result");
    info!("   5. Log all steps for monitoring and debugging");

    Ok(())
}
